
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
#include "ac_protocol.h"

#include <chrono>
#include <thread>
#include <string.h>
#include "libscapi/include/primitives/Matrix.hpp"
#include "ProtocolParty.h"
#pragma once

#define LC log4cpp::Category::getInstance(m_logcat)

template <class T>
class cc_coin_toss : public ac_protocol
{
	size_t m_rounds;
	int share_size;
	std::vector <T> m_secrets, generated_shares;
	vector<unsigned char> random_bytes;
	std::string fieldType;
	T sum=0;
    TemplateField<T> * temp;

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
		vector<unsigned char> shares_bytes, received_shares_bytes, sum_shares_bytes, data;
		std::vector< T > received_shares, received_sum_shares;
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

	int generate_data(std::vector<T>&);

	vector<T> secrets;

	bool valid_shares();

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
    if(!fieldType.compare("Mersenne31")) {
        share_size = 8;
        temp = new TemplateField<T>(2147483647);
    }
    else {
        share_size = 16;
        temp = new TemplateField<T>(0);
    }
}

template <class T>
cc_coin_toss<T>::~cc_coin_toss()
{
    delete temp;
}

template <class T>
int cc_coin_toss<T>::run(const size_t id, const size_t parties, const char * conf_file, const size_t rounds, const size_t idle_timeout_seconds)
{
    LC.notice("%s: running protocol.", __FUNCTION__);
    m_rounds = rounds;

    for(int i = 0; i < m_rounds; i ++) {
        ac_protocol::run_ac_protocol(id, parties, conf_file, idle_timeout_seconds);
    }

    return 1;
}

template <class T>
int cc_coin_toss<T>::pre_run()
{
    m_secrets.clear();
    m_party_states.clear();
    m_party_states.resize(m_parties);

    for(int i = 0; i < m_party_states.size(); i++) {
        party_t &peer(m_party_states[i]);
        peer.shares_bytes.resize(share_size);

    }

    generated_shares.resize(m_party_states.size());

    vector<T> s;
    generate_data(s);

    return 0;
}

template <class T>
int cc_coin_toss<T>::post_run()
{

    if(!valid_shares()){
        LC.info("%s: shares not valid", __FUNCTION__);
    }else{
        LC.info("%s: shares valid", __FUNCTION__);
    }

    return 0;
}

// change function to generate shares of a random value
template <class T>
int cc_coin_toss<T>::generate_data(std::vector<T>& secret)
{
    int result = -1;
    T s = 1000;
    m_secrets.resize(2);
//    m_secrets[0] = s;
//    m_secrets[1] = s;
    random_bytes.resize(8);
    RAND_bytes(random_bytes.data(), 8);
    m_secrets[0] = temp->bytesToElement(&random_bytes[0]);
    random_bytes.clear();
    RAND_bytes(random_bytes.data(), 8);
    m_secrets[1] = temp->bytesToElement(&random_bytes[0]);

    party_t & self(m_party_states[m_id]);
    self.received_shares.resize(2);
    //m_secrets.push_back(2000);

    ProtocolParty<T> ss(fieldType);
    generated_shares = ss.generate_shares(m_secrets, 6, 2, 2);   // generalise this later and use the argument of the function



    self.received_shares[0] = generated_shares[m_id];

    return result;
}

template <class T>
bool cc_coin_toss<T>::valid_shares()
{
    bool recons;
    ProtocolParty<T> ss(fieldType);

    vector<T> sum_shares;
    sum_shares.resize(m_party_states.size());
    for (int i = 0; i < m_party_states.size(); i++) {
        party_t &peer(m_party_states[i]);
        sum_shares[i] = peer.received_sum_shares[0];
    }
    recons = ss.reconstruct(sum_shares, 2, 3);
    secrets=ss.secrets;
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
    self.shares_bytes.resize(1);
    self.sum_shares_bytes.resize(1);

    unsigned char* thing;
    switch(peer.state)
    {
        case ps_nil:
            return false;

        case ps_send_sum_share:
            LC.info("%s: reached sending sum share %lu", __FUNCTION__, party_id);
            temp->elementToBytes(&self.sum_shares_bytes[0], self.received_sum_shares[0]);

            if(0 != m_cc->send(party_id, &self.sum_shares_bytes[0], share_size)) {
                LC.error("%s: party id %lu share send failure.", __FUNCTION__, party_id);
                return (m_run_flag = false);
            }
            else {
                peer.state = ps_receive_sum_share;
            }

        case ps_receive_sum_share:
            if(!peer.data.empty())
                {
                    size_t chunk_size = share_size;
                    //if(peer.data.size() < chunk_size) chunk_size = peer.data.size();
                    peer.sum_shares_bytes.insert(peer.sum_shares_bytes.end(), peer.data.data(), peer.data.data() + chunk_size);
                    T elem;
                    elem = temp->bytesToElement(&peer.sum_shares_bytes[0]);
                    //peer.received_shares.erase(peer.received_shares.begin(), peer.received_shares.end());
                    peer.received_sum_shares.insert(peer.received_sum_shares.end(), elem);
                    peer.data.erase(peer.data.begin(), peer.data.begin() + chunk_size);
                }
                if(peer.sum_shares_bytes.size() < share_size)       // FIX THIS AND MAKE IT WORK
                    return false;//wait for more data

            peer.state=ps_round_up;
        case ps_round_up:
            return true;
        case ps_connected:

            temp->elementToBytes(&peer.shares_bytes[0], generated_shares[party_id]);
            LC.info("%s: reached connected %lu", __FUNCTION__, party_id);
            LC.info("%s: sending %lu to party %d",__FUNCTION__, peer.shares_bytes[0], party_id);
            if(0 != m_cc->send(party_id, &peer.shares_bytes[0], share_size))
            {
                LC.error("%s: party id %lu share send failure.", __FUNCTION__, party_id);
                return (m_run_flag = false);
            }
            else {
                LC.error("%s: party id %lu share send NOT failure.", __FUNCTION__, party_id);
                peer.state = ps_shares_sent;
            }
        case ps_shares_sent:
            LC.info("%s: reached shares sent %lu", __FUNCTION__, party_id);
            if(!peer.data.empty())
                {
                    size_t chunk_size = share_size;
                    //if(peer.data.size() < chunk_size) chunk_size = peer.data.size();

                    peer.received_shares_bytes.insert(peer.received_shares_bytes.end(), peer.data.data(), peer.data.data() + chunk_size);
                    T elem;
                    elem = temp->bytesToElement(&peer.received_shares_bytes[0]);
                    //peer.received_shares.erase(peer.received_shares.begin(), peer.received_shares.end());
                    LC.debug("%s: receiving share %lu from party %d", __FUNCTION__, peer.received_shares_bytes[0], party_id);
                    peer.received_shares.insert(peer.received_shares.end(), elem);
                    peer.data.erase(peer.data.begin(), peer.data.begin() + chunk_size);
                }
            else{
                LC.info("%s: its empty :(", __FUNCTION__);
                return false;
            }
            if(peer.shares_bytes.size() < share_size) {
                return false;
            }


            peer.state = ps_first_round_up;
            /* no break */

            return true;
        case ps_first_round_up:
            return true;
        default:
            LC.error("%s: invalid party state value %u.", __FUNCTION__, peer.state);
            exit(__LINE__);
    }

}

template <class T>
bool cc_coin_toss<T>::round_up()
{
    bool first_round = true, second_round = true;
    LC.debug("%s: round up", __FUNCTION__);
    for(int i = 0; i < m_party_states.size(); i++) {
        if(i == m_id) continue;
        if(ps_first_round_up != m_party_states[i].state){
            first_round = false;
            //
        }

    }

    if(first_round) {
        LC.debug("%s: yay first round is over", __FUNCTION__);
        for (int i = 0; i < m_party_states.size(); i++) {
            party_t & peer2(m_party_states[i]);

            LC.debug("%s made pointer to party %lu, value is %lu", __FUNCTION__, i, peer2.received_shares[0]);
            sum = sum + peer2.received_shares[0];
        }
        LC.debug("%s: computed sum", __FUNCTION__);
        party_t & me(m_party_states[m_id]);
        me.received_sum_shares.insert(me.received_sum_shares.end(), sum);

        for(int i = 0; i < m_party_states.size(); i++) {
            m_party_states[i].state = ps_send_sum_share;
        }
        LC.info("%s: if first_round round up", __FUNCTION__);
        return true;
    }


    for(size_t pid = 0; pid < m_parties; ++pid)
    {
        if(pid == m_id) continue;
        if(ps_round_up != m_party_states[pid].state) {
            second_round = false;
            LC.debug("%s: party %lu not ready for round 2", __FUNCTION__, pid);
        }
    }

    if(second_round){
        LC.debug("%s: round 2 done", __FUNCTION__);
        return (m_run_flag=false);
    }

    return true;
}