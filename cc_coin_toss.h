
#pragma once

template <class T>
class cc_coin_toss : public ac_protocol
{
	size_t m_rounds;
	std::vector <T> m_secrets;
	std::vector <T> generated_shares;
	std::string fieldType;
	T sum;
	std::vector<T> sum_shares;

	typedef enum
	{
		ps_nil = 0,
		ps_connected,
		ps_shares_sent,
        ps_send_sum_share,
        ps_receive_sum_share,
        ps_first_round_up,
		ps_round_up
	}party_state_t;

	typedef struct __party_t
	{
		party_state_t state;
		std::vector< T > data, shares_rcvd, secrets;
		__party_t():state(ps_nil){}
	}party_t;

	std::vector< cc_coin_toss::party_t > m_party_states;

	void handle_party_conn(const size_t party_id, const bool connected);
	void handle_party_msg(const size_t party_id, std::vector< u_int8_t > & msg);

	int pre_run();
	bool run_around();
	bool party_run_around(const size_t party_id);
	bool round_up();
	int post_run();

	int generate_data(std::vector<T>&) const;

	int valid_shares() const;

public:
	cc_coin_toss(const comm_client_factory::client_type_t cc_type, comm_client::cc_args_t * cc_args);
	virtual ~cc_coin_toss();

	int run(const size_t id, const size_t parties, const char * conf_file, const size_t rounds, const size_t idle_timeout_seconds);
};

