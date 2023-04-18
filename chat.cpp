#include <curses.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>
#include <getopt.h>
#include <string>
using std::string;
#include <deque>
using std::deque;
#include <pthread.h>
#include <utility>
using std::pair;
#include "dh.h"
#include "crypto.h"
#include <iostream>
using namespace std;

string username;

static pthread_t thread_receive_message; /* wait for incoming messagess and post to queue */
void *receive_message(void *);			 /* for thread_receive_message */
static pthread_t thread_curses;			 /* setup curses and draw messages from queue */
void *curses_thread_manager(void *);	 /* for thread_curses */
/* thread_curses will get a queue full of these and redraw the appropriate windows */
struct redraw_data
{
	bool resize;
	string msg;
	string sender;
	WINDOW *win;
};
static deque<redraw_data> message_queue; /* messages and resizes yet to be drawn */
/* manage access to message queue: */
static pthread_mutex_t message_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t message_queue_cond = PTHREAD_COND_INITIALIZER;

/* XXX different colors for different senders */

/* record chat history as deque of strings: */
static deque<string> transcript;

#define max(a, b) \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

int listen_socket, socket_fd;

[[noreturn]] static void fail_exit(const char *msg);

[[noreturn]] static void perror_fail_exit(const char *msg)
{
	perror(msg);
	fail_exit("");
}

struct ChatClient
{
	string aes_key;
	string aes_iv;
	string hmac_key;
	RSA *my_rsa_keys;
	RSA *their_rsa_public_key;

	const string DELIMITER = ";;;";

	ChatClient(string aes_key, string aes_iv, string hmac_key, RSA *my_rsa_key, RSA *their_rsa_public_key) : aes_key(aes_key), aes_iv(aes_iv), hmac_key(hmac_key), my_rsa_keys(my_rsa_key), their_rsa_public_key(their_rsa_public_key) {}

	ssize_t send(string message)
	{
		// send length of message as fixed-size integer
		size_t length = message.length();
		uint32_t length_nbo = htonl(length);
		if (-1 == ::send(socket_fd, &length_nbo, sizeof(length_nbo), 0))
		{
			perror("send");
			return -1;
		}
		// send message
		return ::send(socket_fd, message.c_str(), length, 0);
	}

	ssize_t send_secure(string message)
	{
		string message_encrypted = aes_encrypt(aes_key, aes_iv, message);
		string hmac = hmac_sha512(hmac_key, message);
		string hmac_encrypted = rsa_private_encrypt(my_rsa_keys, hmac);
		return send(message_encrypted + DELIMITER + hmac_encrypted);
	}

	string receive()
	{
		// receive length of message as fixed-size integer
		uint32_t length_nbo;
		if (recv(socket_fd, &length_nbo, sizeof(length_nbo), 0) == -1)
		{
			perror("recv");
			return "";
		}
		ssize_t length = ntohl(length_nbo);
		// receive message, ensuring that the entire message is received
		char buffer[length + 1];
		ssize_t bytes_received = 0;
		while (bytes_received < length)
		{
			ssize_t bytes_received_now = recv(socket_fd, buffer + bytes_received, length - bytes_received, 0);
			if (-1 == bytes_received_now)
			{
				perror("recv");
				return "";
			}
			bytes_received += bytes_received_now;
		}
		buffer[bytes_received] = '\0';
		// return as string
		return string(reinterpret_cast<char *>(buffer), length);
	}

	string receive_secure()
	{
		string received = receive();

		if (received.empty())
			return "";

		size_t separator = received.find(DELIMITER);

		if (separator == string::npos)
			fail_exit("Received message without delimiter");

		string message_encrypted = received.substr(0, separator);
		string message = aes_decrypt(aes_key, aes_iv, message_encrypted);

		string hmac_encrypted = received.substr(separator + 3);
		string hmac = rsa_public_decrypt(their_rsa_public_key, hmac_encrypted);

		if (hmac != hmac_sha512(hmac_key, message))
			fail_exit("HMAC mismatch");

		return message;
	}
};

ChatClient *chat_client;

void init_chat_session()
{
	// generate Diffie-Hellman public key and private key
	printf("Generating Diffie-Hellman session keys...\n");
	dh_load_params_from_file("params");
	NEWZ(a); /* secret key (a random exponent) */
	NEWZ(A); /* public key: A = g^a mod p */
	dh_generate_key_pair(a, A);

	// send public key to other party
	string dh_public_key_string = mpz_get_str(NULL, 10, A);
	chat_client->send(dh_public_key_string);

	// receive public key from other party
	mpz_t B;
	string other_dh_public_key_string = chat_client->receive();
	mpz_init_set_str(B, other_dh_public_key_string.c_str(), 10);

	// compute shared Diffie-Hellman secret
	printf("Computing shared Diffie-Hellman secret...\n");
	size_t DH_SECRET_LENGTH = 128;
	unsigned char shared_secret[DH_SECRET_LENGTH];
	dh_compute_shared_secret(a, A, B, shared_secret, DH_SECRET_LENGTH);

	// derive AES key and IV from shared secret
	printf("Deriving AES key and IV from shared secret...\n");
	SessionKeys session_keys = derive_session_keys(shared_secret, DH_SECRET_LENGTH);

	// generate RSA keypair
	printf("Generating RSA key...\n");
	RSA *my_rsa_keys = rsa_generate_key();

	// exchange RSA public keys
	printf("Exchanging RSA public keys...\n");
	string my_rsa_public_key_string = rsa_public_key_to_string(my_rsa_keys);
	chat_client->send(my_rsa_public_key_string);
	string their_rsa_public_key_string = chat_client->receive();
	RSA *their_rsa_public_key = rsa_public_key_from_string(their_rsa_public_key_string);

	// ask user to accept RSA key fingerprint, using an SSH-like prompt
	while (1)
	{
		printf("\nThe authenticity of the other user cannot be established.\n");
		printf("RSA key fingerprint is %s.\n", rsa_public_key_fingerprint(their_rsa_public_key).c_str());
		printf("Are you sure you want to continue connecting (y/n)? ");

		char accept;
		cin >> accept;

		if (accept == 'y' || accept == 'Y')
		{
			chat_client->send("y");
			break;
		}
		else if (accept == 'n' || accept == 'N')
		{
			chat_client->send("n");
			fail_exit("Exiting...");
		}
	}

	// wait for y from other user
	if (chat_client->receive() != "y")
	{
		fail_exit("The other user did not accept your key fingerprint. Exiting...");
	}

	// configure chat client
	chat_client = new ChatClient(session_keys.aes_key, session_keys.aes_iv, session_keys.hmac_key, my_rsa_keys, their_rsa_public_key);

	// test
	printf("Testing chat client...\n");
	chat_client->send_secure("Hello, world!");
	if (chat_client->receive_secure() != "Hello, world!")
	{
		fail_exit("Encrypted message test failed");
	}

	printf("Chat session initialized.\n");
}

void authenticate_other_party()
{
	printf("Authenticating other party... ");

	// send encrypted challenge
	string challenge = random_string(32);
	string encrypted_challenge = rsa_public_encrypt(chat_client->their_rsa_public_key, challenge);
	if (chat_client->send_secure(encrypted_challenge) < 0)
	{
		perror("Failed to send challenge message");
		exit(1);
	}

	// receive decrypted response
	string challenge_response = chat_client->receive_secure();

	// send result
	string challenge_result = challenge_response == challenge ? "pass" : "fail";
	if (chat_client->send_secure(challenge_result) < 0)
	{
		perror_fail_exit("Failed to send challenge result");
	}

	if (challenge_result == "pass")
	{
		printf("success\n");
	}
	else
	{
		fail_exit("Failed to authenticate other party");
	}
}

void authenticate_self()
{
	printf("Authenticating self... ");

	// receive encrypted challenge
	string encrypted_challenge = chat_client->receive_secure();

	// send decrypted response
	string challenge = rsa_private_decrypt(chat_client->my_rsa_keys, encrypted_challenge);
	if (chat_client->send_secure(challenge) < 0)
	{
		perror_fail_exit("Failed to send challenge response");
	}

	// receive result
	string challenge_result = chat_client->receive_secure();

	if (challenge_result == "pass")
	{
		printf("success\n");
	}
	else
	{
		fail_exit("Challenge failed");
	}
}

int init_server_network(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listen_socket = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listen_socket < 0)
		perror_fail_exit("ERROR opening socket");
	bzero((char *)&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listen_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		perror_fail_exit("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n", port);
	listen(listen_socket, 1);
	socklen_t clilen;
	struct sockaddr_in cli_addr;
	socket_fd = accept(listen_socket, (struct sockaddr *)&cli_addr, &clilen);
	if (socket_fd < 0)
		perror_fail_exit("error on accept");
	close(listen_socket);
	/* at this point, should be able to send/recv on socket_fd */

	// exchange DH and RSA keys to set up the encrypted chat client
	fprintf(stderr, "connection made, starting session...\n");
	init_chat_session();

	// perform mutual authentication (client first)
	authenticate_other_party();
	authenticate_self();

	fprintf(stderr, "Mutual authentication successful, starting chat...\n");

	return 0;
}

static int init_client_network(char *hostname, int port)
{
	struct sockaddr_in serv_addr;
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (socket_fd < 0)
		perror_fail_exit("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL)
	{
		fprintf(stderr, "ERROR, no such host\n");
		exit(0);
	}
	bzero((char *)&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(socket_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		perror_fail_exit("ERROR connecting");
	/* at this point, should be able to send/recv on socket_fd */

	// exchange DH and RSA keys to set up the encrypted chat client
	fprintf(stderr, "Connected to server, initializing session...\n");
	init_chat_session();

	// perform mutual authentication (client first)
	authenticate_self();
	authenticate_other_party();

	fprintf(stderr, "Mutual authentication successful, starting chat...\n");

	return 0;
}

static int shutdown_network()
{
	shutdown(socket_fd, 2);
	unsigned char dummy[64];
	ssize_t r;
	do
	{
		r = recv(socket_fd, dummy, 64, 0);
	} while (r != 0 && r != -1);
	close(socket_fd);
	return 0;
}

/* end network stuff. */

[[noreturn]] static void fail_exit(const char *msg)
{
	// Make sure endwin() is only called in visual mode. As a note, calling it
	// twice does not seem to be supported and messed with the cursor position.
	if (!isendwin())
		endwin();
	fprintf(stderr, "%s\n", msg);
	exit(EXIT_FAILURE);
}

// Checks errors for (most) ncurses functions. CHECK(fn, x, y, z) is a checked
// version of fn(x, y, z).
#define CHECK(fn, ...)                                  \
	do                                                  \
		if (fn(__VA_ARGS__) == ERR)                     \
			fail_exit(#fn "(" #__VA_ARGS__ ") failed"); \
	while (false)

static bool should_exit = false;

// Message window
static WINDOW *msg_win;
// Separator line above the command (readline) window
static WINDOW *sep_win;
// Command (readline) window
static WINDOW *cmd_win;

// Input character for readline
static unsigned char input;

static int readline_getc(FILE *dummy)
{
	return input;
}

/* if batch is set, don't draw immediately to real screen (use wnoutrefresh
 * instead of wrefresh) */
static void redisplay_message_window(bool batch, const string &newmsg = "", const string &sender = "")
{
	if (batch)
		wnoutrefresh(msg_win);
	else
	{
		wattron(msg_win, COLOR_PAIR(2));
		wprintw(msg_win, "%s:", sender.c_str());
		wattroff(msg_win, COLOR_PAIR(2));
		wprintw(msg_win, " %s\n", newmsg.c_str());
		wrefresh(msg_win);
	}
}

static void handle_readline_input(char *line)
{
	string mymsg;
	if (!line)
	{
		// Ctrl-D pressed on empty line
		should_exit = true;
		/* XXX send a "goodbye" message so other end doesn't
		 * have to wait for timeout on recv()? */
	}
	else
	{
		if (*line)
		{
			add_history(line);
			mymsg = string(line);
			transcript.push_back(username + ": " + mymsg);
			if (chat_client->send_secure(username + ": " + mymsg) == -1)
				perror_fail_exit("send failed");
		}
		pthread_mutex_lock(&message_queue_mutex);
		message_queue.push_back({false, mymsg, "me", msg_win});
		pthread_cond_signal(&message_queue_cond);
		pthread_mutex_unlock(&message_queue_mutex);
	}
}

/* if batch is set, don't draw immediately to real screen (use wnoutrefresh
 * instead of wrefresh) */
static void redisplay_command_window(bool batch)
{
	int prompt_width = strnlen(rl_display_prompt, 128);
	int cursor_col = prompt_width + strnlen(rl_line_buffer, rl_point);

	werase(cmd_win);
	mvwprintw(cmd_win, 0, 0, "%s%s", rl_display_prompt, rl_line_buffer);
	/* XXX deal with a longer message than the terminal window can show */
	if (cursor_col >= COLS)
	{
		// Hide the cursor if it lies outside the window. Otherwise it'll
		// appear on the very right.
		curs_set(0);
	}
	else
	{
		wmove(cmd_win, 0, cursor_col);
		curs_set(1);
	}
	if (batch)
		wnoutrefresh(cmd_win);
	else
		wrefresh(cmd_win);
}

static void readline_redisplay(void)
{
	pthread_mutex_lock(&message_queue_mutex);
	message_queue.push_back({false, "", "", cmd_win});
	pthread_cond_signal(&message_queue_cond);
	pthread_mutex_unlock(&message_queue_mutex);
}

static void handle_window_resize(void)
{
	if (LINES >= 3)
	{
		wresize(msg_win, LINES - 2, COLS);
		wresize(sep_win, 1, COLS);
		wresize(cmd_win, 1, COLS);
		/* now move bottom two to last lines: */
		mvwin(sep_win, LINES - 2, 0);
		mvwin(cmd_win, LINES - 1, 0);
	}

	/* Batch refreshes and commit them with doupdate() */
	redisplay_message_window(true);
	wnoutrefresh(sep_win);
	redisplay_command_window(true);
	doupdate();
}

static void init_ncurses(void)
{
	if (!initscr())
		fail_exit("Failed to initialize ncurses");

	if (has_colors())
	{
		CHECK(start_color);
		CHECK(use_default_colors);
	}
	CHECK(cbreak);
	CHECK(noecho);
	CHECK(nonl);
	CHECK(intrflush, NULL, FALSE);

	curs_set(1);

	if (LINES >= 3)
	{
		msg_win = newwin(LINES - 2, COLS, 0, 0);
		sep_win = newwin(1, COLS, LINES - 2, 0);
		cmd_win = newwin(1, COLS, LINES - 1, 0);
	}
	else
	{
		// Degenerate case. Give the windows the minimum workable size to
		// prevent errors from e.g. wmove().
		msg_win = newwin(1, COLS, 0, 0);
		sep_win = newwin(1, COLS, 0, 0);
		cmd_win = newwin(1, COLS, 0, 0);
	}
	if (!msg_win || !sep_win || !cmd_win)
		fail_exit("Failed to allocate windows");

	scrollok(msg_win, true);

	if (has_colors())
	{
		// Use white-on-blue cells for the separator window...
		CHECK(init_pair, 1, COLOR_WHITE, COLOR_BLUE);
		CHECK(wbkgd, sep_win, COLOR_PAIR(1));
		/* NOTE: -1 is the default background color, which for me does
		 * not appear to be any of the normal colors curses defines. */
		CHECK(init_pair, 2, COLOR_MAGENTA, -1);
	}
	else
	{
		wbkgd(sep_win, A_STANDOUT); /* c.f. man curs_attr */
	}
	wrefresh(sep_win);
}

static void deinit_ncurses(void)
{
	delwin(msg_win);
	delwin(sep_win);
	delwin(cmd_win);
	endwin();
}

static void init_readline(void)
{
	// Let ncurses do all terminal and signal handling
	rl_catch_signals = 0;
	rl_catch_sigwinch = 0;
	rl_deprep_term_function = NULL;
	rl_prep_term_function = NULL;

	// Prevent readline from setting the LINES and COLUMNS environment
	// variables, which override dynamic size adjustments in ncurses. When
	// using the alternate readline interface (as we do here), LINES and
	// COLUMNS are not updated if the terminal is resized between two calls to
	// rl_callback_read_char() (which is almost always the case).
	rl_change_environment = 0;

	// Handle input by manually feeding characters to readline
	rl_getc_function = readline_getc;
	rl_redisplay_function = readline_redisplay;

	rl_callback_handler_install("> ", handle_readline_input);
}

static void deinit_readline(void)
{
	rl_callback_handler_remove();
}

static const char *usage =
	"Usage: %s [OPTIONS]...\n"
	"Secure chat for CSc380.\n\n"
	"   -c, --connect HOST  Attempt a connection to HOST.\n"
	"   -l, --listen        Listen for new connections.\n"
	"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
	"   -h, --help          show this message and exit.\n";

int main(int argc, char *argv[])
{
	// define long options
	static struct option long_opts[] = {
		{"connect", required_argument, 0, 'c'},
		{"listen", no_argument, 0, 'l'},
		{"port", required_argument, 0, 'p'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}};
	// process options:
	int c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX + 1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;
	bool isclient = true;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1)
	{
		switch (c)
		{
		case 'c':
			if (strnlen(optarg, HOST_NAME_MAX))
				strncpy(hostname, optarg, HOST_NAME_MAX);
			break;
		case 'l':
			isclient = false;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
			printf(usage, argv[0]);
			return 0;
		case '?':
			printf(usage, argv[0]);
			return 1;
		}
	}
	if (isclient)
	{
		init_client_network(hostname, port);
	}
	else
	{
		init_server_network(port);
	}

	// ask for name
	printf("Enter your name: ");
	cin >> username;

	/* NOTE: these don't work if called from curses_thread_manager */
	init_ncurses();
	init_readline();
	/* start curses thread */
	if (pthread_create(&thread_curses, 0, curses_thread_manager, 0))
	{
		fprintf(stderr, "Failed to create curses thread.\n");
	}
	/* start receiver thread: */
	if (pthread_create(&thread_receive_message, 0, receive_message, 0))
	{
		fprintf(stderr, "Failed to create update thread.\n");
	}

	/* put this in the queue to signal need for resize: */
	redraw_data rd = {false, "", "", NULL};
	do
	{
		int c = wgetch(cmd_win);
		switch (c)
		{
		case KEY_RESIZE:
			pthread_mutex_lock(&message_queue_mutex);
			message_queue.push_back(rd);
			pthread_cond_signal(&message_queue_cond);
			pthread_mutex_unlock(&message_queue_mutex);
			break;
			// Ctrl-L -- redraw screen
		// case '\f':
		// 	// Makes the next refresh repaint the screen from scratch
		// 	/* XXX this needs to be done in the curses thread as well. */
		// 	clearok(curscr,true);
		// 	handle_window_resize();
		// 	break;
		default:
			input = c;
			rl_callback_read_char();
		}
	} while (!should_exit);

	shutdown_network();
	deinit_ncurses();
	deinit_readline();
	return 0;
}

/* Let's have one thread responsible for all things curses.  It should
 * 1. Initialize the library
 * 2. Wait for messages (we'll need a mutex-protected queue)
 * 3. Restore terminal / end curses mode? */

/* We'll need yet another thread to listen for incoming messages and
 * post them to the queue. */

void *curses_thread_manager(void *pData)
{
	/* NOTE: these calls only worked from the main thread... */
	// init_ncurses();
	// init_readline();
	while (true)
	{
		pthread_mutex_lock(&message_queue_mutex);
		while (message_queue.empty())
		{
			pthread_cond_wait(&message_queue_cond, &message_queue_mutex);
			/* NOTE: pthread_cond_wait will release the mutex and block, then
			 * reaquire it before returning.  Given that only one thread (this
			 * one) consumes elements of the queue, we probably don't have to
			 * check in a loop like this, but in general this is the recommended
			 * way to do it.  See the man page for details. */
		}
		/* at this point, we have control of the queue, which is not empty,
		 * so write all the messages and then let go of the mutex. */
		while (!message_queue.empty())
		{
			redraw_data m = message_queue.front();
			message_queue.pop_front();
			if (m.win == cmd_win)
			{
				redisplay_command_window(m.resize);
			}
			else if (m.resize)
			{
				handle_window_resize();
			}
			else
			{
				redisplay_message_window(false, m.msg, m.sender);
				/* Redraw input window to "focus" it (otherwise the cursor
				 * will appear in the transcript which is confusing). */
				redisplay_command_window(false);
			}
		}
		pthread_mutex_unlock(&message_queue_mutex);
	}
	return 0;
}

void *receive_message(void *)
{
	chat_client->send_secure(username + ": joined the chat.");
	while (1)
	{
		string message = chat_client->receive_secure();
		if (message.empty())
		{
			/* signal to the main loop that we should quit: */
			should_exit = true;
			return 0;
		}
		size_t pos = message.find(": ");
		string username = message.substr(0, pos);
		message = message.substr(pos + 2);

		pthread_mutex_lock(&message_queue_mutex);
		message_queue.push_back({false, message, username, msg_win});
		pthread_cond_signal(&message_queue_cond);
		pthread_mutex_unlock(&message_queue_mutex);
	}
	return 0;
}
