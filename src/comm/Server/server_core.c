#include <my_global.h>
#include <mysql.h>
#include <my_sys.h>
#include "../client_server.h"

#define DATABASE_USER_NAME "manager"
#define DATABASE_USER_PASSWD "manager"
#define DATABASE_NAME "railway_ticket_system"

static MYSQL* db_conn;
static MYSQL_ROW row;
static MYSQL_RES* res_set;

static FILE* read_file;
static FILE* write_file;
static FILE* log_file;
static char content[BUFFER_SIZE];
static long int current_client_id;

int handle_finish_request();
int handle_login_request();
int handle_order_request();
int handle_refund_request();
int handle_register_request();
int handle_query_booked_ticket_request();
int handle_query_by_station_request();

void print_mysql_error(MYSQL* conn, char* message);

int run_server_core(FILE* read, FILE* write, FILE* log)
{
	// init the static variable
	read_file = read;
	write_file = write;
	log_file = log;
	current_client_id = -1;
	
	// connect database
	db_conn = mysql_init(NULL);
	if(db_conn == NULL)
	{
		fprintf(stderr, "mysql_init() failed\n");
		return -1;
	}
	if(mysql_real_connect(db_conn, "localhost", DATABASE_USER_NAME, DATABASE_USER_PASSWD, DATABASE_NAME, 0, NULL, 0) == NULL)
	{
		fprintf(stderr, "mysql_real_connect() failed\n");
		mysql_close(db_conn);
		return -1;
	}

	int request;
	do
	{	
		errno = 0; // clear the errno
		if(read_line(content, sizeof(content), read_file, false) == NULL)
		{
			if(feof(read_file))
			{
				fprintf(stdout, "client close its connection abruptly\n");
				return 0;
			}
			else
			{
				fprintf(stderr, "can't get user request: %s\n", strerror(errno));
				return -1;
			}
		}
		request = atoi(content);
		switch (request)
		{
			case FINISH_REQUEST:
				if(handle_finish_request() == -1)
				{
					fprintf(stderr, "handle finish request error\n");
					return -1;
				}
				break;
			case REGISTER_REQUEST:
				if(handle_register_request() == -1)
				{
					fprintf(stderr, "handle register request error\n");
					return -1;
				}
				break;
			case LOGIN_REQUEST:
				if(handle_login_request() == -1)
				{
					fprintf(stderr, "handle login request error\n");
					return -1;
				}
				break;
			case QUERY_BY_STATION_REQUEST:
				if(handle_query_by_station_request() == -1)
				{
					fprintf(stderr, "handle query by station request error\n");
					return -1;
				}
				break;
			case ORDER_REQUEST:
				if(handle_order_request() == -1)
				{
					fprintf(stderr, "handle order request error\n");
					return -1;
				}
				break;
			case QUERY_BOOKED_TICKET_REQUEST:
				if(handle_query_booked_ticket_request() == -1)
				{
					fprintf(stderr, "handle query booked ticket request error\n");
					return -1;
				}
				break;
			case REFUND_REQUEST:
				if(handle_refund_request() == -1)
				{
					fprintf(stderr, "handle refund request error\n");
					return -1;
				}
				break;
			default:
				fprintf(stderr, "unknown request: %d\n", request);
				return -1;
		}
	} while(request != FINISH_REQUEST);

	mysql_close(db_conn);
	return 0;
}

int handle_finish_request()
{
	#ifdef __DEBUG__
	printf("handle finish request\n");
	#endif
	snprintf(content, sizeof(content), "%d\n", FINISH_ACK);
	Write(fileno(write_file), content, sizeof(char) * strlen(content));

	return 0;
}

int handle_login_request()
{
	#ifdef __DEBUG__
	printf("handle login request\n");
	#endif
	char name[MAX_STRING];
	char passwd[MAX_STRING];
	int login_result;

	if(read_line(name, sizeof(name), read_file, false) == NULL)
	{
		fprintf(stderr, "can't get user name\n");
		return -1;
	}
	remove_ending_line_break(name);

	if(read_line(passwd, sizeof(passwd), read_file, false) == NULL)
	{
		fprintf(stderr, "can't get user password\n");
		return -1;
	}
	remove_ending_line_break(passwd);

	snprintf(content, sizeof(content), "SELECT id, password FROM client WHERE name = '%s'", name);
	if(mysql_query(db_conn, content) != 0)
	{
		print_mysql_error(db_conn, "can't retrieve user password");
		return -1;
	}
	else
	{
		res_set = mysql_store_result(db_conn);
		if(res_set == NULL)
		{
			print_mysql_error(db_conn, "mysql_store_result() failed");
			login_result = FAILURE;
		}
		else
		{
			if(mysql_num_rows(res_set) == 0)
			{
				login_result = FAILURE;
			}
			else
			{
				row = mysql_fetch_row(res_set);
				if(strcmp(passwd, row[1]) == 0)
				{
					login_result = SUCCESS;
					//record current user
					current_client_id = atoi(row[0]);
				}
				else
				{
					login_result = FAILURE;
				}
			}
		}
		mysql_free_result(res_set);
    }

	// send response
	snprintf(content, sizeof(content), "%d\n%d\n", LOGIN_RESPONSE, login_result);
	Write(fileno(write_file), content, sizeof(char) * strlen(content));

	return 0;
}

int handle_register_request()
{

	#ifdef __DEBUG__
	printf("handle register request\n");
	#endif
	char name[MAX_STRING];
	char passwd[MAX_STRING];
	int  register_result;

	if(read_line(name, sizeof(name), read_file, false) == NULL)
	{
		fprintf(stderr, "can't get user name\n");
		return -1;
	}
	remove_ending_line_break(name);

	if(read_line(passwd, sizeof(passwd), read_file, false) == NULL)
	{
		fprintf(stderr, "can't get user password\n");
		return -1;
	}
	remove_ending_line_break(passwd);

	snprintf(content, sizeof(content), "INSERT INTO client (name, password) VALUES ('%s', '%s')", name, passwd);
	if(mysql_query(db_conn, content) != 0)
	{
		print_mysql_error(db_conn, "can't create new user");
		register_result = FAILURE;
	}
	else
	{
		register_result = SUCCESS;
	}

	// send response
	snprintf(content, sizeof(content), "%d\n%d\n", REGISTER_RESPONSE, register_result);
	Write(fileno(write_file), content, sizeof(char) * strlen(content));

	return 0;
}

int handle_query_by_station_request()
{

	#ifdef __DEBUG__
	printf("handle query by station request\n");
	#endif
	char start_station[MAX_STRING];
	char end_station[MAX_STRING];

	if(read_line(start_station, sizeof(start_station), read_file, false) == NULL)
	{
		fprintf(stderr, "can't get start station\n");
		return -1;
	}
	remove_ending_line_break(start_station);

	if(read_line(end_station, sizeof(end_station), read_file, false) == NULL)
	{
		fprintf(stderr, "can't get end station\n");
		return -1;
	}
	remove_ending_line_break(end_station);
	
	snprintf(content, sizeof(content), "SELECT t.name, sta1.name, sta2.name, ADDTIME(t.departure_time, SEC_TO_TIME(sch1.cost_time * 60)), \
			sch2.cost_time - sch1.cost_time, sch2.cost_money - sch1.cost_money \
			FROM schedule sch1, schedule sch2, station sta1, station sta2, train t \
			WHERE sch1.train_id = sch2.train_id AND sch1.train_id = t.id AND sch1.station_id = sta1.id \
			AND sch2.station_id = sta2.id AND sch1.cost_time < sch2.cost_time AND sta1.name = '%s' AND sta2.name = '%s'", 
			start_station, end_station);

	if(mysql_query(db_conn, content) != 0)
	{
		print_mysql_error(db_conn, "can't retrieve satisfied train");
		return -1;
	}
	else
	{
		res_set = mysql_store_result(db_conn);
		if(res_set == NULL)
		{
			print_mysql_error(db_conn, "mysql_store_result() failed");
			return -1;
		}
		else
		{
			int result_number = mysql_num_rows(res_set);

			snprintf(content, sizeof(content), "%d\n%d\n", QUERY_BY_STATION_RESPONSE, result_number);
			Write(fileno(write_file), content, sizeof(char) * strlen(content));

			int i;
			for(i = 0; i < result_number; i++)
			{
				row = mysql_fetch_row(res_set);
				snprintf(content, sizeof(content), "%s\n%s\n%s\n%s\n%s\n\%s\n", row[0], row[1], row[2], row[3], row[4], row[5]);
				Write(fileno(write_file), content, sizeof(char) * strlen(content));
			}
		}
		mysql_free_result(res_set);
	}
	
	return 0;
}

int handle_order_request()
{
	#ifdef __DEBUG__
	printf("handle order request\n");
	#endif
	char train_name[MAX_STRING];
	char start_station[MAX_STRING];
	char end_station[MAX_STRING];
	char departure_time_str[MAX_STRING];
	char arrival_time_str[MAX_STRING];
	int  ticket_number;
	int  ticket_money;
	long int train_id;
	long int start_station_id;
	long int end_station_id;

	read_line(train_name, sizeof(train_name), read_file, true);
	remove_ending_line_break(train_name);

	read_line(start_station, sizeof(start_station), read_file, true);
	remove_ending_line_break(start_station);

	read_line(end_station, sizeof(end_station), read_file, true);
	remove_ending_line_break(end_station);

	read_line(departure_time_str, sizeof(departure_time_str), read_file, true);
	remove_ending_line_break(departure_time_str);

	read_line(arrival_time_str, sizeof(arrival_time_str), read_file, true);
	remove_ending_line_break(arrival_time_str);

	ticket_number = atoi(read_line(content, sizeof(content), read_file, true));
	ticket_money = atoi(read_line(content, sizeof(content), read_file, true));

	// get train id
	snprintf(content, sizeof(content), "SELECT id FROM train WHERE name = '%s'", train_name);
	if(mysql_query(db_conn, content) != 0)
	{
		print_mysql_error(db_conn, "can't get train id");
		return -1;
	}
	else
	{
		res_set = mysql_store_result(db_conn);
		if(res_set == NULL)
		{
			print_mysql_error(db_conn, "mysql_store_result() failed");
			return -1;
		}
		row = mysql_fetch_row(res_set);
		train_id = atol(row[0]);
		mysql_free_result(res_set);
	}

	// get start station id
	snprintf(content, sizeof(content), "SELECT id FROM station WHERE name = '%s'", start_station);
	if(mysql_query(db_conn, content) != 0)
	{
		print_mysql_error(db_conn, "can't get start station id");
		return -1;
	}
	else
	{
		res_set = mysql_store_result(db_conn);
		if(res_set == NULL)
		{
			print_mysql_error(db_conn, "mysql_store_result() failed");
			return -1;
		}
		row = mysql_fetch_row(res_set);
		start_station_id = atol(row[0]);
		mysql_free_result(res_set);
	}

	// get end station id
	snprintf(content, sizeof(content), "SELECT id FROM station WHERE name = '%s'", end_station);
	if(mysql_query(db_conn, content) != 0)
	{
		print_mysql_error(db_conn, "can't get end station id");
		return -1;
	}
	else
	{
		res_set = mysql_store_result(db_conn);
		if(res_set == NULL)
		{
			print_mysql_error(db_conn, "mysql_store_result() failed");
			return -1;
		}
		row = mysql_fetch_row(res_set);
		end_station_id = atol(row[0]);
		mysql_free_result(res_set);
	}

	snprintf(content, sizeof(content), "SELECT id, name FROM seat WHERE train_id = %ld \
			AND id NOT IN (SELECT seat_id FROM ticket WHERE train_id = %ld \
			AND ((departure_time >= '%s' AND departure_time < '%s') OR (arrival_time > '%s' AND arrival_time <= '%s')))",
			train_id, train_id, departure_time_str, arrival_time_str, departure_time_str, arrival_time_str);	
	if(mysql_query(db_conn, content) != 0)
	{
		print_mysql_error(db_conn, "can't get available seats");
		return -1;
	}
	else
	{
		res_set = mysql_store_result(db_conn);
		
		int result_number = mysql_num_rows(res_set);
		if(result_number <  ticket_number)
		{
			// no available seats
			snprintf(content, sizeof(content), "%d\n%d\n", ORDER_RESPONSE, FAILURE);
			Write(fileno(write_file), content, sizeof(char) * strlen(content));
		}
		else
		{
			snprintf(content, sizeof(content), "%d\n%d\n", ORDER_RESPONSE, SUCCESS);
			Write(fileno(write_file), content, sizeof(char) * strlen(content));
			
			int i;
			long int seat_id;
			for(i = 0; i < ticket_number; i++)
			{
				row = mysql_fetch_row(res_set);
				seat_id = atol(row[0]);
				snprintf(content, sizeof(content), "INSERT INTO ticket \
						(client_id, train_id, seat_id, start_station_id, end_station_id, departure_time, arrival_time, price) \
						VALUES (%ld, %ld, %ld, %ld, %ld, '%s', '%s', %d)",
						current_client_id, train_id, seat_id, start_station_id, end_station_id,
						departure_time_str, arrival_time_str, ticket_money);
				if(mysql_query(db_conn, content) != 0)
				{
					print_mysql_error(db_conn, "can't insert ticket");
				}


				// send seat name
				snprintf(content, sizeof(content), "%s\n", row[1]);
				Write(fileno(write_file), content, sizeof(char) * strlen(content));
			}

			// order log
			if(log_file != NULL)
			{
				time_t current_time_t = time(0);
				char current_time_str[50];
				strftime(current_time_str, 50, "%Y-%m-%d %H:%M:%S", localtime(&current_time_t));
				snprintf(content, sizeof(content), "Client %ld buy %d ticket(s) from %ld to %ld, take train %ld, order time %s\n", \
						current_client_id, ticket_number, start_station_id, end_station_id, train_id, current_time_str);
				fputs(content, log_file);
			}
		}
		mysql_free_result(res_set);
	}

	return 0;
}

int handle_refund_request()
{
	#ifdef __DEBUG__
	printf("handle refund request\n");
	#endif
	
	int refund_result;
	long int ticket_id = atol(read_line(content, sizeof(content), read_file, true));

	snprintf(content, sizeof(content), "DELETE FROM ticket WHERE id = %ld", ticket_id);
	if(mysql_query(db_conn, content) != 0)
	{
		print_mysql_error(db_conn, "can't delete the ticket");
		refund_result = FAILURE;
	}
	else
	{
		// refund order
		if(log_file != NULL)
		{
			snprintf(content, sizeof(content), "Client %ld refund a ticket\n", current_client_id);
			fputs(content, log_file);
		}
		refund_result = SUCCESS;
	}

	// send response
	snprintf(content, sizeof(content), "%d\n%d\n", REFUND_RESPONSE, refund_result);
	Write(fileno(write_file), content, sizeof(char) * strlen(content));

	return 0;
}

int handle_query_booked_ticket_request()
{
	#ifdef __DEBUG__
	printf("handle query booked ticket request\n");
	#endif
	
	snprintf(content, sizeof(content), "SELECT tic.id, tra.name, sta1.name, sta2.name, tic.departure_time \
			FROM ticket tic, train tra, station sta1, station sta2 \
			WHERE tic.client_id = %ld AND tic.departure_time > CURRENT_TIMESTAMP \
			AND tic.train_id = tra.id AND tic.start_station_id = sta1.id AND tic.end_station_id = sta2.id", current_client_id);

	if(mysql_query(db_conn, content) != 0)
	{
		print_mysql_error(db_conn, "can't retrieve booked ticket");
		return -1;
	}
	else
	{
		res_set = mysql_store_result(db_conn);
		if(res_set == NULL)
		{
			print_mysql_error(db_conn, "mysql_store_result() failed");
			return -1;
		}
		else
		{
			int result_number = mysql_num_rows(res_set);

			snprintf(content, sizeof(content), "%d\n%d\n", QUERY_BOOKED_TICKET_RESPONSE, result_number);
			Write(fileno(write_file), content, sizeof(char) * strlen(content));

			int i;
			for(i = 0; i < result_number; i++)
			{
				row = mysql_fetch_row(res_set);
				snprintf(content, sizeof(content), "%s\n%s\n%s\n%s\n%s\n", row[0], row[1], row[2], row[3], row[4]);
				Write(fileno(write_file), content, sizeof(char) * strlen(content));
			}
		}
		mysql_free_result(res_set);
	}

	return 0;
}

// this function is a facility
void print_mysql_error(MYSQL* conn, char* message)
{
	fprintf(stderr, "%s\n", message);
	if(conn != NULL)
	{
	#if MYSQL_VERSION_ID >= 40101
		fprintf(stderr, "Error %u (%s): %s\n", mysql_errno(conn), mysql_sqlstate(conn), mysql_error(conn));
	#else
		fprintf(stderr, "Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
	#endif
	}
}
