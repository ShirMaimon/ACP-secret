
#include <stdlib.h>
#include <semaphore.h>
#include <memory.h>
#include <stdio.h>
#include <errno.h>

#include <string>
#include <vector>
#include <list>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <log4cpp/Category.hh>
#include <event2/event.h>

#include "comm_client_cb_api.h"
#include "comm_client.h"
#include "comm_client_factory.h"
#include "lfq.h"
#include "ac_protocol.h"

#include <chrono>
#include <thread>
#include <string.h>
#include "libscapi/include/primitives/Matrix.hpp"
#include "ProtocolParty.h"
#pragma once

#define SHARE_BYTE_SIZE		8
#define LC log4cpp::Category::getInstance(m_logcat)

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

	bool valid_shares() const;

public:
	cc_coin_toss(const comm_client_factory::client_type_t cc_type, comm_client::cc_args_t * cc_args, std::string field);
	virtual ~cc_coin_toss();

	int run(const size_t id, const size_t parties, const char * conf_file, const size_t rounds, const size_t idle_timeout_seconds);
};


using namespace std;
template <class T>
cc_coin_toss<T>::cc_coin_toss(const comm_client_factory::client_type_t cc_type, comm_client::cc_args_t * cc_args, string field)
    : ac_protocol(cc_type, cc_args), m_rounds(0)
{
    fieldType = field;
}

template <class T>
cc_coin_toss<T>::~cc_coin_toss()
{
}

template <class T>
int cc_coin_toss<T>::run(const size_t id, const size_t parties, const char * conf_file, const size_t rounds, const size_t idle_timeout_seconds)
{
    LC.notice("%s: running protocol.", __FUNCTION__);
    m_rounds = rounds;
    return ac_protocol::run_ac_protocol(id, parties, conf_file, idle_timeout_seconds);
}

template <class T>
int cc_coin_toss<T>::pre_run()
{
    m_secrets.clear();
    m_party_states.clear();
    m_party_states.resize(m_parties);

    // Rewrite to generate randomness for packed multiplication

//	if(0 != generate_data(m_id, m_party_states[m_id].seed, m_party_states[m_id].commit))
//	{
//		LC.error("%s: self data generation failed; toss failure.", __FUNCTION__);
//		return -1;
//	}
    return 0;
}

template <class T>
int cc_coin_toss<T>::post_run()
{
//	m_party_states.clear();
//
//	if(m_secrets.size() != m_rounds)
//	{
//		LC.error("%s: invalid number of toss results %lu out of %lu; toss failure.", __FUNCTION__, m_secrets.size(), m_rounds);
//		return -1;
//	}
//	size_t round = 0;
//	for(std::list< std::vector< u_int8_t > >::const_iterator toss = m_secrets.begin(); toss != m_secrets.end(); ++toss, ++round)
//	{
//		LC.info("%s: toss result %lu = <%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X>",
//				__FUNCTION__, round,
//				(*toss)[0], (*toss)[1], (*toss)[2], (*toss)[3], (*toss)[4], (*toss)[5], (*toss)[6], (*toss)[7],
//				(*toss)[8], (*toss)[9], (*toss)[10], (*toss)[11], (*toss)[12], (*toss)[13], (*toss)[14], (*toss)[15]);
//	}
    return 0;
}

// change function to generate shares of a random value
template <class T>
int cc_coin_toss<T>::generate_data(std::vector<T>& secret) const
{
    int result = -1;
    m_secrets.push_back(1000);
    //m_secrets.push_back(2000);

    ProtocolParty<T> ss(fieldType);
    generated_shares = ss.generate_shares(m_secrets[0], 6, 1, 2);   // generalise this later and use the argument of the function

    party_t & peer(m_party_states[m_id]);

    peer.shares_rcvd.insert(peer.shares_rcvd.end(), generated_shares.data(), generated_shares.data() + generated_shares.size());

//	if(RAND_bytes(seed.data(), 16))
//	{
//		if(0 == (result = commit_seed(id, seed, commit)))
//			LC.debug("%s: %lu data generated.", __FUNCTION__, id);
//		else
//			LC.error("%s: commit_seed() failed.", __FUNCTION__);
//	}
//	else
//		LC.error("%s: RAND_bytes() failed.", __FUNCTION__);
    return result;
}

// reconstruct from all the shares received and check consistency
template <class T>
bool cc_coin_toss<T>::valid_shares() const
{
    bool recons;
    ProtocolParty<T> ss(fieldType);
    recons = ss.reconstruct(sum_shares, 1, 2);
    return recons;
}

template <class T>
void cc_coin_toss<T>::handle_party_conn(const size_t party_id, const bool connected)
{
    party_t & peer(m_party_states[party_id]);

    if(connected)
    {
        if(ps_nil == peer.state)
        {
            LC.debug("%s: party %lu is now connected.", __FUNCTION__, party_id);
            peer.state = ps_connected;
        }
        else
            LC.warn("%s: party %lu unexpectedly again connected.", __FUNCTION__, party_id);
    }
    else
    {
        bool OK =
            (
                (m_secrets.size() == m_rounds)
                //(m_secrets.size() == (m_rounds - 1) && peer.state > ps_share_for_recon_sent)
                //      modify condition so that seed byte size is parameterised to the share size (8 for M31 and 16 for M61)
//				||
//				(m_secrets.size() == (m_rounds - 1) && peer.state == ps_share_for_recon_sent && SEED_BYTE_SIZE <= (peer.seed.size() + peer.data.size()))
            );

        if(!OK)
        {
            LC.error("%s: party id %lu premature disconnection; toss failed.", __FUNCTION__, party_id);
            m_run_flag = false;
        }
        else
        {
            LC.debug("%s: party %lu is now disconnected.", __FUNCTION__, party_id);
        }
    }
}

template <class T>
void cc_coin_toss<T>::handle_party_msg(const size_t party_id, std::vector< u_int8_t > & msg)
{
    party_t & peer(m_party_states[party_id]);
//  insert the received data into the buffer "data"
    peer.data.insert(peer.data.end(), msg.data(), msg.data() + msg.size());
}

template <class T>
bool cc_coin_toss<T>::run_around()
{
    bool round_ready = true;
    for(size_t pid = 0; pid < m_parties; ++pid)
    {
        if(pid == m_id) continue;
        round_ready = round_ready && party_run_around(pid);//(ps_round_up == m_party_states[pid].state);
    }
    return round_ready;
}


template <class T>
bool cc_coin_toss<T>::party_run_around(const size_t party_id)
{
    party_t & peer(m_party_states[party_id]);
    party_t & self(m_party_states[m_id]);
    T elem = self.shares_rcvd[party_id];
    unsigned char * shares_rcvd_bytes, *sum_bytes;
    if(fieldType.compare("Mersenne31")) {
        memcpy(shares_rcvd_bytes, (byte*)(&elem), 4);
        memcpy(sum_bytes, (byte*)(&sum), 4);
    }
    else {
        memcpy(shares_rcvd_bytes, (byte*)(&elem), 8);
        memcpy(sum_bytes, (byte*)(&sum), 8);
    }


    switch(peer.state)
    {
        case ps_nil:
            return false;
        case ps_connected:

            if(0 != m_cc->send(party_id, shares_rcvd_bytes, SHARE_BYTE_SIZE))
            {
                LC.error("%s: party id %lu share send failure.", __FUNCTION__, party_id);
                return (m_run_flag = false);
            }
            else
                peer.state = ps_shares_sent;
            /* no break */

        case ps_first_round_up:

            peer.state = ps_send_sum_share;

        case ps_send_sum_share:
            if(0 != m_cc->send(party_id, sum_bytes, SHARE_BYTE_SIZE)) {
                LC.error("%s: party id %lu share send failure.", __FUNCTION__, party_id);
                return (m_run_flag = false);
            }
            else {
                peer.state = ps_receive_sum_share;
            }

        case ps_receive_sum_share:
            if(sum_shares.size() < SHARE_BYTE_SIZE)      // write an if condition and check according to fieldType
            {
                if(!peer.data.empty())
                {
                    size_t chunk_size = SHARE_BYTE_SIZE;
                    //if(peer.data.size() < chunk_size) chunk_size = peer.data.size();
                    sum_shares.insert(sum_shares.end(), peer.data.data(), peer.data.data() + chunk_size);
                    peer.data.erase(peer.data.begin(), peer.data.begin() + chunk_size);
                }

                if(sum_shares.size() < SHARE_BYTE_SIZE)
                    return false;//wait for more data
            }
            if(valid_shares()) {
                peer.state = ps_round_up;
            }


        case ps_shares_sent:
            if(peer.shares_rcvd.size() < SHARE_BYTE_SIZE)      // write an if condition and check according to fieldType
            {
                if(!peer.data.empty())
                {
                    size_t chunk_size = SHARE_BYTE_SIZE;
                    //if(peer.data.size() < chunk_size) chunk_size = peer.data.size();
                    peer.shares_rcvd.insert(peer.shares_rcvd.end(), peer.data.data(), peer.data.data() + chunk_size);
                    peer.data.erase(peer.data.begin(), peer.data.begin() + chunk_size);
                }

                if(peer.shares_rcvd.size() < SHARE_BYTE_SIZE)
                    return false;//wait for more data
            }
            peer.state = ps_first_round_up;
            /* no break */
            return true;
        case ps_round_up:
            return true;
        default:
            LC.error("%s: invalid party state value %u.", __FUNCTION__, peer.state);
            exit(__LINE__);
    }

}

template <class T>
bool cc_coin_toss<T>::round_up()
{
    int pid =0;
    if(ps_first_round_up==m_party_states[pid].state){
        for (int i = 0; i < m_party_states.size(); i++) {
            party_t & peer2(m_party_states[i]);
            sum = sum + peer2.shares_rcvd[0];
        }
        sum_shares.push_back(sum);
    }
    for(size_t pid = 0; pid < m_parties; ++pid)
    {
        if(pid == m_id) continue;
        if(ps_round_up != m_party_states[pid].state)
            return false;
    }

//	std::vector<u_int8_t> toss(SHARE_BYTE_SIZE, 0);
//	for(size_t pid = 0; pid < m_parties; ++pid)
//	{
//		for(size_t j = 0; j < SHARE_BYTE_SIZE; ++j)
//			toss[j] ^= m_party_states[pid].seed[j];
//		m_party_states[pid].commit.clear();
//		m_party_states[pid].seed.clear();
//		m_party_states[pid].state = ps_connected;
//	}

//	m_toss_outcomes.push_back(toss);
//	if(m_toss_outcomes.size() == m_rounds)
//	{
//		LC.notice("%s: done tossing; all results are in.", __FUNCTION__);
//		return (m_run_flag = false);
//	}

//	if(0 != generate_data(m_id, m_party_states[m_id].seed, m_party_states[m_id].commit))
//	{
//		LC.error("%s: self data generation failed; toss failure.", __FUNCTION__);
//		exit(__LINE__);
//	}

    return true;
}