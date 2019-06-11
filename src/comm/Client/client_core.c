#define _XOPEN_SOURCE 600

#include <curses.h>
#include "../client_server.h"

#define QUIT             0
#define LOGIN            1
#define REGISTER         2
#define BOOK             3
#define REFUND           4
#define QUERY_BY_STATION 5
#define BACK			 6

#define ERROR_COLOR      1

/* variable declaration */
extern int LINES;
extern int COLS;

static FILE* read_file;
static FILE* write_file;

static int   choice;
static char* get_choice_title = "login or register";

static char* login_menu[]    = {"login", "register", "quit", 0};
static int   login_command[] = {LOGIN,   REGISTER,   QUIT};

static char*  operation_menu[]    = {"book tickets", "refund tickets", "quit", 0};
static int    operation_command[] = {BOOK,			 REFUND,		   QUIT};

static char* query_menu[]    = {"query by station", "<<back", 0};
static int   query_command[] = {QUERY_BY_STATION,	BACK};

static char** current_menu    = login_menu;
static int*   current_command = login_command;

static char content[BUFFER_SIZE];

/* function declaration */
void show_welcome_interface();

// this two functions are facility functions, get user choice by menu
void draw_menu(char* options[], int current_highlight, int start_y, int start_x);
int getchoice(char* greet, char* choices[], int commands[]);

int run_quit_module();
int run_book_module();
int run_login_module();
int run_refund_module();
int run_register_module();
int run_query_by_train_module();
int run_query_by_station_module();
int run_order_module(char* train_name, char* start_station, char* end_station, char* start_time, int cost_time, int cost_money);

void get_string(char* string, int max_length);
void show_error(int start_y, int start_x, char* message);
void get_passwd(char* passwd, int max_length, int start_y, int start_x);

int run_client_core(FILE* read, FILE* write)
{
	// init the staic variable
	read_file = read;
	write_file = write;

	int client_core_result = 0; // reocrd whether client core succeeds or fails
	
	// set up curses
	initscr();
	start_color();
	init_pair(ERROR_COLOR, COLOR_RED, COLOR_WHITE);	

	show_welcome_interface();
	do
	{
		choice = getchoice(get_choice_title, current_menu, current_command); 
		switch (choice)
		{
			case QUIT:
				if(run_quit_module() == -1)
				{
					fprintf(stderr, "quit module has error\n");
					client_core_result = -1;
				}
				break;
			case LOGIN:
				if(run_login_module() == -1)
				{
					fprintf(stderr, "login module has error\n");
					client_core_result = -1;
				}
				break;
			case REGISTER:
				if(run_register_module() == -1)
				{
					fprintf(stderr, "register module has error\n");
					client_core_result = -1;
				}
				break;
			case BOOK:
				if(run_book_module() == -1)
				{
					fprintf(stderr, "book module has error\n");
					client_core_result = -1;
				}
				break;
			case REFUND:
				if(run_refund_module() == -1)
				{
					fprintf(stderr, "refund module has error\n");
					client_core_result = -1;
				}
				break;
		}
	} while (choice != QUIT && client_core_result != -1);

	// clean up curses
	endwin();

	return client_core_result;
}

/* 
 * display a welcome slogan in the middle of the screen
 */
void show_welcome_interface()
{
	
	const char welcome_slogan[] = "Welcome to";
	const char system_name[] = "Railway Ticket System";

	int middle_y = LINES   / 2;

	int start_x = (COLS - strlen(welcome_slogan)) / 2;
	int start_y = middle_y - 1;
	
	const char* scan_ptr;

	clear(); // clear the screen
	attron(A_DIM);
	scan_ptr = welcome_slogan + strlen(welcome_slogan) - 1;
	while(scan_ptr >= welcome_slogan)
	{
		move(start_y, start_x);
		insch(*(scan_ptr--));
		refresh();
	}
	
	start_x = (COLS - strlen(system_name)) / 2;
	start_y = middle_y + 1;

	scan_ptr = system_name + strlen(system_name) - 1;
	while(scan_ptr >= system_name)
	{
		move(start_y, start_x);
		insch(*(scan_ptr--));
		refresh();
	}

	attroff(A_DIM);
	sleep(1);
}

/*
 * this function is from Beginning Linux Programming and is modified
 * @param choices the string representation of all choices
 * @param commands the internal representation of all choices. choices and commands have a one-to-one relation
 */
int getchoice(char* greet, char* choices[], int commands[])
{
	static int selected_row = 0;

	int max_row = 0;
	char** option;
	option = choices;
	while(*option)
	{
		max_row++;
		option++;
	}

	int start_y = 0;
	int start_x = 0;
	int selected;
	int key = 0;

	if(selected_row >= max_row)
	{
		selected_row = 0;
	}

	clear();
	mvprintw(start_y, start_x, greet);
	
	keypad(stdscr, true);
	cbreak();
	noecho();
	key = 0;
	while(key != KEY_ENTER && key != '\n'){
		if(key == KEY_UP)
		{
			if(selected_row == 0)
			{
				selected_row = max_row - 1;
			}
			else
			{
				selected_row--;
			}
		}
		if(key == KEY_DOWN)
		{
			if(selected_row == (max_row - 1))
			{
				selected_row = 0;
			}
			else
			{
				selected_row++;
			}
		}
		selected = commands[selected_row];
		draw_menu(choices, selected_row, start_y + 2, start_x);
		key = getch();
	}
	keypad(stdscr, false);
	nocbreak();
	echo();

	return selected;
}

/*
 * this function is also from Beginning Linux Programming and is modified
 */
void draw_menu(char* options[], int current_highlight, int start_y, int start_x)
{
	int current_row = 0;
	char** option_ptr;
	char* txt_ptr;
	option_ptr = options;
	while(*option_ptr)
	{
		if(current_row == current_highlight)
		{
			attron(A_STANDOUT);
		}
		txt_ptr = options[current_row];
		mvprintw(start_y + current_row * 2, start_x, "%s", txt_ptr);
		if(current_row == current_highlight)
		{
			attroff(A_STANDOUT);
		}
		current_row++;
		option_ptr++;
	}

	mvprintw(start_y + current_row * 2 + 3, start_x, "Move highlight then press Return");
	refresh();
}

int run_quit_module()
{
	// notify the server
	snprintf(content, sizeof(content), "%d\n", FINISH_REQUEST);
	Write(fileno(write_file), content, sizeof(char) * strlen(content));

	// get reponse
	if(read_line(content, sizeof(content), read_file, false) == NULL)
	{
		fprintf(stderr, "can't get server quit ack\n");
		return -1;
	}
	if(atoi(content) != FINISH_ACK)
	{
		fprintf(stderr, "expect quit_ack but get %s\n", content);
		return -1;
	}

	return 0;
}

int run_login_module()
{
	char name[MAX_STRING];
	char passwd[MAX_STRING]; 
	char* name_hint           = "Enter the user name:   ";
	char* passwd_hint         = "Enter the password:    ";
	char* name_passwd_invalid = "User name and password are invalid";

	clear();

	// get user name
	int start_y = 0;
	int start_x = 0;
	mvprintw(start_y, start_x, "%s", name_hint);
	get_string(name, MAX_STRING);

	// get password
	start_y = start_y + 2;
	mvprintw(start_y, start_x, "%s", passwd_hint);
	get_passwd(passwd, sizeof(passwd), start_y, start_x + strlen(passwd_hint));	

	//verify at server
	snprintf(content, sizeof(content), "%d\n%s\n%s\n", LOGIN_REQUEST, name, passwd);
	Write(fileno(write_file), content, sizeof(char) * strlen(content));

	// get response
	if(read_line(content, sizeof(content), read_file, false) == NULL)
	{
		fprintf(stderr, "can't get login response\n");
		return -1;
	}
	if(atoi(content) != LOGIN_RESPONSE)
	{
		fprintf(stderr, "expect login_response but get %s\n", content);
		return -1;
	}
	read_line(content, sizeof(content), read_file, true);

	if(atoi(content) == FAILURE)
	{
		start_y = start_y + 2;
		show_error(start_y, start_x, name_passwd_invalid);
		sleep(2);
	}
	else
	{
		// set the global current_menu and current_command so we will go to the operation interface
		current_menu     = operation_menu;
		current_command  = operation_command;
		get_choice_title = "select an operation";
	}
	return 0;
}

int run_register_module()
{
	char  name[MAX_STRING];
	char  passwd[MAX_STRING];
	char  confirm_passwd[MAX_STRING];
	char* name_hint           = "Enter the user name:      ";
	char* passwd_hint         = "Enter the password:       ";
	char* confirm_passwd_hint = "Enter the password again:  ";
	char* passwd_not_same     = "Passwords are not same";
	char* user_exist          = "This user name is not available";
	int   start_y;
	int   start_x;

	clear();

	// get user name
	start_y = 0;
	start_x = 0;
	mvprintw(start_y, start_x, "%s", name_hint);
	get_string(name, sizeof(name));

	// get password
	start_y = start_y + 2;
	mvprintw(start_y, start_x, "%s", passwd_hint);
	get_passwd(passwd, sizeof(passwd), start_y, start_x + strlen(passwd_hint));

	// get confirm passwd
	start_y = start_y + 2;
	mvprintw(start_y, start_x, "%s", confirm_passwd_hint);
	get_passwd(confirm_passwd, sizeof(confirm_passwd), start_y, start_x + strlen(confirm_passwd_hint));
	
	if(strcmp(passwd, confirm_passwd) != 0)
	{
		start_y = start_y + 2;
		show_error(start_y, start_x, passwd_not_same);
		sleep(2);
		return 0;
	}
	
	// update server
	snprintf(content, sizeof(content), "%d\n%s\n%s\n", REGISTER_REQUEST, name, passwd);
	Write(fileno(write_file), content, sizeof(char) * strlen(content));

	// get response
	if(read_line(content, sizeof(content), read_file, false) == NULL)
	{
		fprintf(stderr, "can't get register response\n");
		return -1;
	}
	if(atoi(content) != REGISTER_RESPONSE)
	{
		return -1;
	}
	read_line(content, sizeof(content), read_file, true);

	if(atoi(content) == FAILURE)
	{
		start_y = start_y + 2;
		show_error(start_y, start_x, user_exist);
		sleep(2);
	}

	return 0;
}

int run_book_module()
{
	get_choice_title = "select query mode";
	int choice;
	do
	{
		choice = getchoice(get_choice_title, query_menu, query_command);
		switch(choice)
		{
			case QUERY_BY_STATION:
				if(run_query_by_station_module() == -1)
				{
					fprintf(stderr, "query by station module has error\n");
					return -1;
				}
				break;
			case BACK:
				break;
		}
	} while (choice != BACK);

	return 0;
}

int run_query_by_station_module()
{
	char  start_station[MAX_STRING];
	char  end_station[MAX_STRING];
	char* start_station_hint = "Enter the start station:   ";
	char* end_station_hint   = "Enter the end station:     ";
	char* station_not_exist  = "The start station or end station is not exist"; // TODO unused variable
	char* station_same       = "The start station is same with end station";
	char* no_available_train = "No available trains";
	int   start_y;
	int   start_x;
	int   query_result_num;

	clear();

	// get start station
	start_y = 0;
	start_x = 0;
	mvprintw(start_y, start_x, "%s", start_station_hint);
	get_string(start_station, sizeof(start_station));

	// get end station
	start_y = start_y + 2;
	mvprintw(start_y, start_x, "%s", end_station_hint);
	get_string(end_station, sizeof(end_station));

	if(strcmp(start_station, end_station) == 0) // start_station shouldn't be equal to end_station
	{
		start_y = start_y + 2;
		show_error(start_y, start_x, station_same);
		sleep(2);
		return 0;
	}

	// query server
	snprintf(content, sizeof(content), "%d\n%s\n%s\n", QUERY_BY_STATION_REQUEST, start_station, end_station);
	Write(fileno(write_file), content, sizeof(char) * strlen(content));

	// get response
	if(read_line(content, sizeof(content), read_file, false) == NULL)
	{
		fprintf(stderr, "can't get query_by_station response\n");
		return -1;
	}
	if(atoi(content) != QUERY_BY_STATION_RESPONSE)
	{
		return -1;
	}

	read_line(content, sizeof(content), read_file, true);

	query_result_num = atoi(content);
	if(query_result_num == 0)
	{
		start_y = start_y + 2;
		show_error(start_y, start_x, no_available_train);
		sleep(2);
		return 0;
	}
	
	query_by_station_result* query_result_ptr = (query_by_station_result*)malloc(sizeof(query_by_station_result) * query_result_num);
	char** query_result_select_menu = (char**)malloc(sizeof(char*) * (query_result_num + 2)); // add 2 because last item of the menu array is always 0, which is required by getchoice function and we also add a 'back' menu item
	query_result_select_menu[query_result_num + 1] = 0;
	int* query_result_select_command = (int*)malloc(sizeof(int) * (query_result_num + 1));

	int i;
	for(i = 0; i < query_result_num; i++)
	{
		// get train name  and remove the ending line break
		read_line(query_result_ptr[i].train_name, sizeof(query_result_ptr[i].train_name), read_file, true);
		remove_ending_line_break(query_result_ptr[i].train_name);

		read_line(query_result_ptr[i].start_station, sizeof(query_result_ptr[i].start_station), read_file, true);	
		remove_ending_line_break(query_result_ptr[i].start_station);

		read_line(query_result_ptr[i].end_station, sizeof(query_result_ptr[i].end_station), read_file, true);
		remove_ending_line_break(query_result_ptr[i].end_station);

		read_line(query_result_ptr[i].start_time, sizeof(query_result_ptr[i].start_time), read_file, true);
		remove_ending_line_break(query_result_ptr[i].start_time);

		query_result_ptr[i].cost_time = atoi(read_line(content, sizeof(content), read_file, true));

		query_result_ptr[i].money = atoi(read_line(content, sizeof(content), read_file, true));

		// add a item to menu
		query_result_select_menu[i] = (char*)malloc(sizeof(char) * BUFFER_SIZE);
		snprintf(query_result_select_menu[i], BUFFER_SIZE, "Train %s From %s To %s Start Time %s Spend Time %d minutes Money %d",
				query_result_ptr[i].train_name, query_result_ptr[i].start_station, query_result_ptr[i].end_station,
				query_result_ptr[i].start_time, query_result_ptr[i].cost_time, query_result_ptr[i].money);

		// add a item to command
		query_result_select_command[i] = i;
	}
	
	// add 'back' menu item and command
	query_result_select_menu[i] = (char*)malloc(sizeof(char) * MAX_STRING);
	snprintf(query_result_select_menu[i], MAX_STRING, "<< back");
	query_result_select_command[i] = i;
	
	// this choice variable is the local one not the global one
	int choice = getchoice("select a train", query_result_select_menu, query_result_select_command);

	if(choice < query_result_num) // user select a train not 'back'
	{
		if(run_order_module(query_result_ptr[choice].train_name, query_result_ptr[choice].start_station, query_result_ptr[choice].end_station,
							query_result_ptr[choice].start_time, query_result_ptr[choice].cost_time, query_result_ptr[choice].money) == -1)
		{
			fprintf(stderr, "run order module has error\n");
		}
	}

	// free resource
	free(query_result_ptr);
	for(i = 0; i < query_result_num + 1; i++)
	{
		free(query_result_select_menu[i]);
	}
	free(query_result_select_menu);
	free(query_result_select_command);

	return 0;
}

int run_order_module(char* train_name, char* start_station, char* end_station, char* start_time, int cost_time, int cost_money)
{
	char  date[MAX_STRING];
	char  ticket_number[MAX_STRING];
	char* date_hint          = "Enter the date of departure like 2012-3-8 :";
	char* ticket_number_hint = "Enter the number of tickets:   ";
	char* no_enough_seats    = "Sorry, no enough seats";
	char* order_success      = "Succeed in booking tickets";
	char* invalid_date       = "Your date is invalid";
	int   start_y;
	int   start_x;

	clear();

	// print summary
	start_y = 0;
	start_x = 0;
	snprintf(content, sizeof(content), "You take %s From %s To %s start time %s cost time %d minutes cost money %d yuan",
			train_name, start_station, end_station, start_time, cost_time, cost_money);
	mvprintw(start_y, start_x, "%s", content);
	
	// get ticket number
	start_y = start_y + 2;
	mvprintw(start_y, start_x, "%s", ticket_number_hint);
	get_string(ticket_number, sizeof(ticket_number));

	// get date
	start_y = start_y + 2;
	mvprintw(start_y, start_x, "%s", date_hint);
	get_string(date, sizeof(date));
	
	//validate the date
	bool is_valid = true;
	struct tm departure_time_tm;
	time_t departure_time_t;
	time_t current_time_t;
	memset(&departure_time_tm, 0, sizeof(struct tm));
	strptime(start_time, "%H:%M:%S", &departure_time_tm);
	if(strptime(date, "%Y-%m-%d", &departure_time_tm) == NULL)
	{
		is_valid = false;
	}
	else
	{
		current_time_t = time(0);
		departure_time_t = mktime(&departure_time_tm);
		if(current_time_t >= departure_time_t) // train already leave
		{
			is_valid = false;
		}
	}
	if(!is_valid)
	{
		start_y = start_y + 2;
		show_error(start_y, start_x, invalid_date);
		sleep(2);
		return run_order_module(train_name, start_station, end_station, start_time, cost_time, cost_money); // TODO recursive may be insecure may use too much memory
	}

	// compute arrival time
	time_t arrival_time_t;
	struct tm* arrival_time_tm_ptr;
	arrival_time_t = departure_time_t + cost_time * 60;
	arrival_time_tm_ptr = localtime(&arrival_time_t);

	// convert time to string representation
	char departure_time_str[MAX_STRING];
	char arrival_time_str[MAX_STRING];
	strftime(departure_time_str, sizeof(departure_time_str), "%Y-%m-%d %H:%M:%S", &departure_time_tm);
	strftime(arrival_time_str, sizeof(arrival_time_str), "%Y-%m-%d %H:%M:%S", arrival_time_tm_ptr);

	// get confirm
	snprintf(content, sizeof(content), "Confirm: You want to book %d tickets From %s To %s by %s start_time %s [yes|no]: ",
			atoi(ticket_number), start_station, end_station, train_name, departure_time_str);
	start_y = start_y + 2;
	mvprintw(start_y, start_x, "%s", content);
	get_string(content, sizeof(content));

	if(strcmp(content, "yes") != 0)
	{
		return 0;
	}

	// query server
	snprintf(content, sizeof(content), "%d\n%s\n%s\n%s\n%s\n%s\n%d\n%d\n", ORDER_REQUEST, train_name, start_station,
			end_station, departure_time_str, arrival_time_str, atoi(ticket_number), cost_money);
	Write(fileno(write_file), content, sizeof(char) * strlen(content));

	//get response
	if(read_line(content, sizeof(content), read_file, false) == NULL)
	{
		fprintf(stderr, "can't get order response\n");
		return -1;
	}
	if(atoi(content) != ORDER_RESPONSE)
	{
		return -1;
	}

	read_line(content, sizeof(content), read_file, true);
	if(atoi(content) == FAILURE)
	{
		start_y = start_y + 2;
		show_error(start_y, start_x, no_enough_seats);
		sleep(2);
	}
	else
	{
		start_y = start_y + 2;
		mvprintw(start_y, start_x, "%s", order_success);

		int i;
		for(i = 0; i < atoi(ticket_number); i++)
		{
			start_y = start_y + 1;
			read_line(content, sizeof(content), read_file, true);
			remove_ending_line_break(content);
			mvprintw(start_y, start_x, "Seat Number: %s", content);
		}

		refresh();
		sleep(3);
	}

	return 0;
}

int run_refund_module()
{
	char* no_ticket      = "Sorry, you don't have any ticket";
	char* refund_success = "Succeed in refunding ticket";
	char* refund_failure = "Oops, refund ticket has a error";
	int   ticket_number;
	int   start_x;
	int   start_y;

	clear();
	start_y = 0;
	start_x = 0;

	// query server, get booked and not expired tickets
	snprintf(content, sizeof(content), "%d\n", QUERY_BOOKED_TICKET_REQUEST);
	Write(fileno(write_file), content, sizeof(char) * strlen(content));

	// get response
	if(read_line(content, sizeof(content), read_file, false) == NULL)
	{
		fprintf(stderr, "can't get query booked ticket response\n");
		return -1;
	}
	if(atoi(content) != QUERY_BOOKED_TICKET_RESPONSE)
	{
		return -1;
	}

	read_line(content, sizeof(content), read_file, true);
	ticket_number = atoi(content);
	if(ticket_number == 0)
	{	
		show_error(start_y, start_x, no_ticket);
		sleep(2);
	}
	else
	{
		query_booked_ticket_result* query_result_ptr = (query_booked_ticket_result*)malloc(sizeof(query_booked_ticket_result) * ticket_number);
		char** query_result_select_menu = (char**)malloc(sizeof(char*) * (ticket_number + 2)); // add 2 because last item of the menu array is always 0, which is required by getchoice function and we also add a 'back' menu item
		query_result_select_menu[ticket_number + 1] = 0;
		int* query_result_select_command = (int*)malloc(sizeof(int) * (ticket_number + 1));

		int i;
		for(i = 0; i < ticket_number; i++)
		{
			query_result_ptr[i].ticket_id = atol(read_line(content, sizeof(content), read_file, true));	

			read_line(query_result_ptr[i].train_name, sizeof(query_result_ptr[i].train_name), read_file, true);
			remove_ending_line_break(query_result_ptr[i].train_name);

			read_line(query_result_ptr[i].start_station, sizeof(query_result_ptr[i].start_station), read_file, true);	
			remove_ending_line_break(query_result_ptr[i].start_station);

			read_line(query_result_ptr[i].end_station, sizeof(query_result_ptr[i].end_station), read_file, true);
			remove_ending_line_break(query_result_ptr[i].end_station);

			read_line(query_result_ptr[i].departure_time, sizeof(query_result_ptr[i].departure_time), read_file, true);
			remove_ending_line_break(query_result_ptr[i].departure_time);

			// add a item to menu
			query_result_select_menu[i] = (char*)malloc(sizeof(char) * BUFFER_SIZE);
			snprintf(query_result_select_menu[i], BUFFER_SIZE, "Ticket: Train %s From %s To %s Departure Time %s",
					query_result_ptr[i].train_name, query_result_ptr[i].start_station, query_result_ptr[i].end_station,
					query_result_ptr[i].departure_time);
			
			// add a item to command
			query_result_select_command[i] = i;
		}

		// add 'back' menu item and command
		query_result_select_menu[i] = (char*)malloc(sizeof(char) * MAX_STRING);
		snprintf(query_result_select_menu[i], MAX_STRING, "<< back");
		query_result_select_command[i] = i;

		int choice = getchoice("select a ticket to refund", query_result_select_menu, query_result_select_command);

		if(choice < ticket_number) // user select a ticket not 'back'
		{
			// notify server to refund the ticket
			snprintf(content, sizeof(content), "%d\n%ld\n", REFUND_REQUEST, query_result_ptr[choice].ticket_id);
			Write(fileno(write_file), content, sizeof(char) * strlen(content));

			// get response
			if(read_line(content, sizeof(content), read_file, false) == NULL)
			{
				fprintf(stderr, "can't get refund response\n");
				return -1;
			}
			if(atoi(content) != REFUND_RESPONSE)
			{
				return -1;
			}
			if(atoi(read_line(content, sizeof(content), read_file, true)) == SUCCESS)
			{
				clear();
				start_y = 0;
				start_x = 0;
				snprintf(content, sizeof(content), "%s", refund_success);
				mvprintw(start_y, start_x, "%s", content);
				refresh();
				flash();
				sleep(2);
			}
			else
			{
				clear();
				start_y = 0;
				start_x = 0;
				snprintf(content, sizeof(content), "%s",refund_failure);
				mvprintw(start_y, start_x, "%s", content);
				refresh();
				flash();
				sleep(2);
			}
		}
		
		// free resource
		free(query_result_ptr);
		for(i = 0; i < ticket_number + 1; i++)
		{
			free(query_result_select_menu[i]);
		}
		free(query_result_select_menu);
		free(query_result_select_command);
	}

	return 0;
}

void get_string(char* string, int max_length)
{
	int len;
	wgetnstr(stdscr, string, max_length);
	len = strlen(string);
	if(len > 0 && string[len - 1] == '\n')
		string[len - 1] = '\0';
}

void get_passwd(char* passwd, int max_length, int start_y, int start_x)
{
	cbreak();
	noecho();
	int i = 0;
	while(i < max_length)
	{
		passwd[i] = getch();
		if(passwd[i] == '\n')
		{
			passwd[i] = '\0';
			break;
		}
		else if(passwd[i] == 127 || passwd[i] == 8)
		{
			if(i != 0)
			{
				i--;
				move(start_y, start_x + i);
				delch();
			}
		}
		else
		{
			move(start_y, start_x + i);
			addch('*');
			i++;
		}
		refresh();
	}
	passwd[max_length - 1] = '\0'; // defensive
	echo();
	nocbreak();
}

void show_error(int start_y, int start_x, char* message)
{
	attron(COLOR_PAIR(ERROR_COLOR));
	mvprintw(start_y, start_x, "%s", message);
	refresh();
	flash();
	attroff(COLOR_PAIR(ERROR_COLOR));
}
