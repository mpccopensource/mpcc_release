#include <linux/module.h>
#include <net/tcp.h>
#include <linux/random.h>
#include <net/mptcp.h>

#define MBPS (1024 * 1024 / 8)
#define PCC_INTERVALS 4

/* Probing changes rate by 5% up and down of current rate. */
#define PCC_PROBING_EPS 5
#define PCC_PROBING_EPS_PART 100

#define PCC_SCALE 1000LL /* scale for fractions, utilities, gradients, ... */
#define PCC_GRAD_TO_RATE_FACTOR 1LL
#define PCC_RATE_MIN 25000
#define PCC_RATE_MIN_PACKETS_PER_RTT 2
#define PCC_INVALID_INTERVAL -1
#define PCC_IGNORE_PACKETS 10
#define PCC_INTERVAL_MIN_PACKETS 1
#define PCC_ALPHA 100
#define PCC_MIN_RATE_CHANGE 62500

#define PCC_GRAD_STEP_SIZE (250)  /* defaults step size for gradient ascent */
#define PCC_MAX_SWING_BUFFER 2 /* number of RTTs to dampen gradient ascent */

/* Rates must differ by at least 2% or gradients are very noisy. */
#define PCC_MIN_RATE_DIFF_RATIO_FOR_GRAD 1

#define PCC_MIN_CHANGE_BOUND 50 /* first rate change is at most 10% of rate */
#define PCC_CHANGE_BOUND_STEP 50 /* consecutive rate changes can go up by 7% */
#define PCC_AMP_MIN 1			 /* starting amplifier for gradient ascent step size */
#define PCC_SLOW_START_ATTEMPTS 2
#define PCC_LAT_INFL_FILTER 30 /* latency inflation below 3% is ignored */

#define USE_PROBING
#define DECISION_HISTORY_SIZE 9

#define TO_MPBPS(r) (((r) * 8) / (1024 * 1024))

#define EMERGENCY_BRAKE_RATIO 300

//#define USE_PERCENTAGES
#define USE_PRINTS

#ifdef USE_PRINTS
#define DBG_PRINT(...) printk(__VA_ARGS__)
#else
#define DBG_PRINT(...)
#endif

enum PCC_DECISION
{
	PCC_RATE_UP = 0,
	PCC_RATE_DOWN,
	PCC_RATE_STAY,
};

struct pcc_interval
{
	u32 rate; /* sending rate of this interval, bytes/sec */

	s64 recv_start; /* timestamps for when interval was waiting for acks */
	s64 recv_end;

	s64 send_start; /* timestamps for when interval data was being sent */
	s64 send_end;

	s64 start_rtt; /* smoothed RTT at start and end of this interval */
	s64 end_rtt;

	u32 packets_sent_base; /* packets sent before this interval started */
	u32 packets_ended;	 

	s64 utility;   /* observed utility of this interval */
	u32 lost;	  /* packets sent during this interval that were lost */
	u32 delivered; /* packets sent during this interval that were delivered */
	u32 throughput;
	s64 loss_ratio;

	u32 start_seq;
	u32 end_seq;
	u64 bytes_lost;
	bool send_ended;
	u32 last_known_seq;
	u32 packets_sent;
	u32 send_end_time;
	u32 timeout;
};

static int id = 0;
struct pcc_data
{
	struct pcc_interval *intervals; /* containts stats for 1 RTT */

	s64 rate;	  /* current sending rate */
	u32 advertised_rate;
	s64 last_rate; /* previous sending rate */
	s64 others_rate;

	u8 start_mode : 1; /* in slow start? */
	u8 moving : 1;	 /* using gradient ascent to move to a new rate? */
	u8 loss_state : 1; 

	u8 wait : 1;	
	u8 swing_buffer : 4;
	u8 send_index;					/* index of interval currently being sent */
	u8 recive_index;				/* index of interval currently receiving acks */
	// debug helpers
	u8 id;
	u8 decisions_count;
	enum PCC_DECISION last_decision; /* most recent rate change direction */
	u32 lost_base;					 /* previously lost packets */
	u32 delivered_base;				 /* previously delivered packets */



	u32 packets_sent;
	u32 packets_counted;
	s32 prev_loss_rate;

	s32 change_bound; /* maximum change as a proportion of the current rate */
	u8 amplifier;	/* multiplier on the current step size */
	u8 slow_start_attempts;
	enum PCC_DECISION* decision_history;
};

/*********************
 * Getters / Setters *
 * ******************/
static s64 mpcc_get_others_rate(struct sock *sk)
{
	struct mptcp_tcp_sock *mptcp_sk;
	struct tcp_sock *tp = tcp_sk(sk);
	struct pcc_data *pcc = inet_csk_ca(sk);
	const struct mptcp_cb *mpcb = tp->mpcb;
	s64 total_rate = 0;

	if (!mptcp(tcp_sk(sk)))
	{
		return 0;
	}
	mptcp_for_each_sub(mpcb, mptcp_sk)
	{
		struct sock *curr_sk = mptcp_to_sock(mptcp_sk);
		//struct tcp_sock *curr_tp = tcp_sk(curr_sk);
		struct pcc_data *curr_pcc = inet_csk_ca(curr_sk);
		if (curr_pcc != pcc)
		{
			total_rate += curr_pcc->advertised_rate;
		}
	}

	return total_rate;
}
static u32 pcc_get_rtt(struct tcp_sock *tp)
{
	/* Get initial RTT - as measured by SYN -> SYN-ACK.
	 * If information does not exist - use 1ms as a "LAN RTT".
	 * (originally from BBR).
	 */
	if (tp->srtt_us)
	{
		return max(tp->srtt_us >> 3, 1U);
	}
	else
	{
		return USEC_PER_MSEC;
	}
}

/* Initialize cwnd to support current pacing rate (but not less then 4 packets)
 */
static void pcc_set_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	u64 cwnd = sk->sk_pacing_rate;
	cwnd *= pcc_get_rtt(tcp_sk(sk));
	cwnd /= tp->mss_cache;

	cwnd /= USEC_PER_SEC;
	//cwnd += 2;
	cwnd *= 2;

	//cwnd = 9000;

	cwnd = max(4ULL, cwnd);
	cwnd = min((u32)cwnd, tp->snd_cwnd_clamp); /* apply cap */
	tp->snd_cwnd = cwnd;
}

/* was the pcc struct fully inited */
bool pcc_valid(struct pcc_data *pcc)
{
	return (pcc && pcc->intervals && pcc->intervals[0].rate);
}

/******************
 * Intervals init *
 * ****************/

/* Set the target rates of all intervals and reset statistics. */
static void pcc_setup_intervals_probing(struct sock *sk, struct pcc_data *pcc)
{
	u32 rate_low, rate_high;
	u32 rate_diff;
	char rand;
	int i;

	get_random_bytes(&rand, 1);
	//if (rand & 1)
		pcc->others_rate = mpcc_get_others_rate(sk);
	rate_diff = (pcc->rate + pcc->others_rate);
	rate_diff /= PCC_PROBING_EPS_PART;
	rate_diff *= PCC_PROBING_EPS;
	rate_diff += (pcc->rate / PCC_PROBING_EPS_PART) * pcc->decisions_count;

	get_random_bytes(&rand, 1);
	rate_high = pcc->rate + rate_diff;
	if (pcc->rate < rate_diff) {
		rate_low = rate_high / 2;
	} else {
		rate_low = pcc->rate - rate_diff;
	}

	/*rate_high = pcc->rate + 2*MBPS;
	rate_low = pcc->rate - 2*MBPS;
	*/

	DBG_PRINT("%d: starting probing, rate: %lld (%lld), rate_high: %u (%u), rate_low: %u (%u) diff: %u (%u)\n", 
	pcc->id, pcc->rate, TO_MPBPS(pcc->rate), rate_high, TO_MPBPS(rate_high), rate_low, TO_MPBPS(rate_low), rate_high - rate_low, TO_MPBPS(rate_high - rate_low));

	for (i = 0; i < PCC_INTERVALS; i += 2)
	{
		if ((rand >> (i / 2)) & 1)
		{
			pcc->intervals[i].rate = rate_low;
			pcc->intervals[i + 1].rate = rate_high;
		}
		else
		{
			pcc->intervals[i].rate = rate_high;
			pcc->intervals[i + 1].rate = rate_low;
		}

		pcc->intervals[i].packets_sent_base = 0;
		pcc->intervals[i + 1].packets_sent_base = 0;
	}

	pcc->send_index = 0;
	pcc->recive_index = 0;
	pcc->wait = false;
	//pcc->others_rate = mpcc_get_others_rate(sk);
	//pcc->advertised_rate = pcc->rate;
}

/* Reset statistics and set the target rate for just one monitor interval */
static void pcc_setup_intervals_moving(struct pcc_data *pcc)
{
	pcc->intervals[0].packets_sent_base = 0;
	if (!pcc->moving) {
		if (pcc->intervals[1].utility < pcc->intervals[0].utility) {
			pcc->intervals[0].utility = pcc->intervals[1].utility;
			pcc->last_rate = pcc->intervals[1].rate;
		}
	}
	pcc->intervals[0].rate = pcc->rate;
	pcc->send_index = 0;
	pcc->recive_index = 0;
	pcc->wait = false;
}

/* Set the pacing rate and cwnd base on the currently-sending interval */
static void start_interval(struct sock *sk, struct pcc_data *pcc)
{
	u32 rate = pcc->rate;
	struct pcc_interval *interval;

	if (!pcc->wait)
	{
		interval = &pcc->intervals[pcc->send_index];
		interval->packets_ended = 0;
		interval->lost = 0;
		interval->delivered = 0;
		interval->packets_sent_base = tcp_sk(sk)->data_segs_out;
		interval->packets_sent_base = max(interval->packets_sent_base, 1U);
		interval->send_start = tcp_sk(sk)->tcp_mstamp;
		rate = interval->rate;
		interval->throughput = 0;
		interval->bytes_lost = 0;
		interval->start_seq = tcp_sk(sk)->snd_nxt;
		interval->end_seq = 0;
		interval->send_ended = false;
		interval->last_known_seq = interval->start_seq - 1;
		interval->loss_ratio = 0;
		interval->packets_sent = 0;
		interval->start_rtt = tcp_sk(sk)->srtt_us >> 3;
		interval->send_end_time = 3 * (tcp_sk(sk)->srtt_us >> 3) / 2;
		interval->timeout = ((tcp_sk(sk)->srtt_us >> 3) * 5) / 2;
	}

	//rate = max(rate, PCC_RATE_MIN);
	if (rate < PCC_RATE_MIN)
		rate = PCC_RATE_MIN;
	rate = min(rate, sk->sk_max_pacing_rate);
	sk->sk_pacing_rate = rate;
	pcc_set_cwnd(sk);
	DBG_PRINT(KERN_INFO "%hhu: starting interval with rate %u (%u)\n", pcc->id, rate, TO_MPBPS(rate));
	DBG_PRINT(KERN_INFO "%hhu: interval start. next seq: %u\n", pcc->id, tcp_sk(sk)->snd_nxt);
}

/************************
 * Utility and decisions *
 * **********************/
/* Calculate the graident of utility w.r.t. sending rate, but only if the rates
 * are far enough apart for the measurment to have low noise.
 */
static s64 pcc_calc_util_grad(s64 rate_1, s64 util_1, s64 rate_2, s64 util_2)
{
	s64 rate_diff_ratio = (PCC_SCALE * (rate_2 - rate_1)) / rate_1;
	if (rate_diff_ratio < PCC_MIN_RATE_DIFF_RATIO_FOR_GRAD &&
		rate_diff_ratio > -1 * PCC_MIN_RATE_DIFF_RATIO_FOR_GRAD)
		return 0;

	return (PCC_SCALE * (util_2 - util_1)) / (rate_2 - rate_1);
}

#define FIXEDPT_BITS 64
#define FIXEDPT_WBITS 40
#define OMIT_STDINT
#include "fixedptc.h"
static void pcc_calc_utility_vivace(struct pcc_data *pcc, struct pcc_interval *interval, struct sock *sk)
{
	s64 delivered, lost, mss, rate, throughput, util;
	s64 send_dur = interval->send_end - interval->send_start;
	s64 recv_dur = interval->recv_end - interval->recv_start;
	s64 recv_throughput = 0;
	s64 old_util = 0;
	fixedpt reward_f = 0;
	s64 reward = 0;
	s64 lat_infl = 0;
    s64 rtt_diff;
	s64 rtt_diff_thresh = 0;
	u64 bytes_sent = interval->end_seq;
	s64 loss_part = 0;
	u32 packets_sent = (interval->end_seq - interval->start_seq) / tcp_sk(sk)->mss_cache;

	interval->utility = 0;
	interval->packets_sent = packets_sent;
	lost = interval->lost;
	lost = interval->bytes_lost;
	delivered = interval->delivered;
	mss = tcp_sk(sk)->mss_cache;
	rate = interval->rate;
	throughput = 0;
	bytes_sent = packets_sent * mss;
	if (send_dur > 0)
		throughput = (USEC_PER_SEC * bytes_sent) / send_dur;
	if (recv_dur > 0)
		recv_throughput = (USEC_PER_SEC * bytes_sent) / recv_dur;
	interval->throughput = throughput;
	if (bytes_sent == 0)
	{
		DBG_PRINT(KERN_INFO "No packets delivered\n");
		//interval->utility = S64_MIN;
		interval->utility = 0;
		return;
	}

	rtt_diff = (interval->end_rtt - interval->start_rtt);
    if (throughput  > 0)
	    rtt_diff_thresh = (2 * USEC_PER_SEC * mss) / throughput;
	if (send_dur > 0)
		lat_infl = (PCC_SCALE * rtt_diff) / (send_dur);
	//lat_infl = 2 * (PCC_SCALE * rtt_diff) / (interval->end_rtt + interval->start_rtt);
	//lat_infl = rtt_diff / USEC_PER_MSEC;
	
	DBG_PRINT(KERN_INFO
		"%hhu: ucalc: lat (%lld->%lld) lat_infl %lld\n",
		 pcc->id, interval->start_rtt / USEC_PER_MSEC, interval->end_rtt / USEC_PER_MSEC,
		 lat_infl);

	//if (rtt_diff < rtt_diff_thresh && rtt_diff > -1 * rtt_diff_thresh)
	//	lat_infl = 0;

	if (lat_infl < PCC_LAT_INFL_FILTER && lat_infl > -1 * PCC_LAT_INFL_FILTER)
		lat_infl = 0;
	
	if (lat_infl < 0 && pcc->start_mode)
		lat_infl = 0;

	//lat_infl = 0;
	/* loss rate = lost packets / all packets counted*/
	interval->loss_ratio = (lost * PCC_SCALE) / (bytes_sent);

	//if (pcc->start_mode)
	//	rate = throughput;

	if (pcc->start_mode && interval->loss_ratio < 150)
		lost = 0;

	//if (interval->loss_ratio < 3) {
	//	lost = 0;
	//}

	if (interval->bytes_lost > bytes_sent) {
		DBG_PRINT(KERN_INFO "bug: lost more bytes than sent\n");
	}
	rate += pcc->others_rate;

	reward_f = fixedpt_fromint(rate);
	reward_f = fixedpt_pow(reward_f, fixedpt_rconst(0.9));
	reward = (reward_f >> FIXEDPT_FBITS);
	loss_part = lost;
	loss_part *= 11;
	loss_part *= rate;
	loss_part /= bytes_sent;
	
	old_util = reward - loss_part - ( (rate * lat_infl)) / PCC_SCALE;
	//old_util =   /*int_sqrt((u64)rate) */ reward - (rate * (11 * lost)) / (lost + delivered) - rate * 900 * lat_infl;
	util = old_util * PCC_GRAD_STEP_SIZE;
	//util = fixedpt_pow(fixedpt_fromint(rate), fixedpt_fromint(1)) - fixedpt_mul(fixedpt_rconst(11.35), fixedpt_mul(fixedpt_fromint(rate), fixedpt_div(fixedpt_fromint((lost)), fixedpt_fromint(lost + delivered))));
	//util >>=  FIXEDPT_FBITS;
	

	DBG_PRINT(KERN_INFO
		   "%hhu ucalc: rate %u (%u) total rate %lld (%lld) sequences %u-%u sent %u delv %lld lost %lld util %lld old_util %lld thpt %lld loss rate %lld\n",
		   pcc->id, interval->rate, (interval->rate * 8) / (1024 * 1024), rate, (rate * 8) / (1024 * 1024), interval->start_seq, interval->end_seq, packets_sent,
		   delivered, lost, util, old_util, throughput, interval->loss_ratio);
	interval->utility = util;
}

static enum PCC_DECISION
pcc_get_decision(struct pcc_data *pcc, u32 new_rate)
{
	if (pcc->rate == new_rate)
		return PCC_RATE_STAY;

	return pcc->rate < new_rate ? PCC_RATE_UP : PCC_RATE_DOWN;
}

static s64 pcc_decide_rate(struct pcc_data *pcc)
{
	bool run_1_res, run_2_res, did_agree;
	s64 grad_1, grad_2;

	run_1_res = pcc->intervals[0].utility > pcc->intervals[1].utility;

	grad_1 = pcc_calc_util_grad(pcc->intervals[0].rate, pcc->intervals[0].utility, pcc->intervals[1].rate, pcc->intervals[1].utility);
	if (PCC_INTERVALS != 4)
		return (run_1_res > 0 ? pcc->intervals[0].rate : pcc->intervals[1].rate);
		//return grad_1;

	run_2_res = pcc->intervals[2].utility > pcc->intervals[3].utility;

	/* did_agree: was the 2 sets of intervals with the same result */
	did_agree = !((run_1_res == run_2_res) ^
				  (pcc->intervals[0].rate == pcc->intervals[2].rate));

	grad_2 = pcc_calc_util_grad(pcc->intervals[2].rate, pcc->intervals[2].utility, pcc->intervals[3].rate, pcc->intervals[3].utility);
	if (did_agree)
	{
		s8 sign;
		s64 ret;
		sign = grad_1 > 0 ? 1 : -1;
		ret = (grad_1 + grad_2) / 2;
		ret = min(abs(grad_1), abs(grad_2)) * sign;
		DBG_PRINT(KERN_INFO "%hhu: pcc_decide_rate: grad_1: %lld grad_2: %lld ret: %lld",
			   pcc->id, grad_1, grad_2, ret);
		//if (run_1_res)
		//	return pcc->intervals[0].rate;
		//else
		//	return pcc->intervals[1].rate;
		return ret;
	}
	else
	{
		return 0;
	}
}

/* Take larger steps if we keep changing rate in the same direction, otherwise
 * reset to take smaller steps again.
 */
static void pcc_update_step_params(struct pcc_data *pcc, s64 step, enum PCC_DECISION decision)
{
	int i;
	int same_decisions = 1;
	//pcc->amplifier = 1;
	if (decision == PCC_RATE_STAY) {
		return;
	}
	if (decision != pcc->last_decision) {
		pcc->change_bound = PCC_MIN_CHANGE_BOUND;
	}
	if ((step > 0) == (pcc->rate > pcc->last_rate))
	{
		if (pcc->swing_buffer > 0)
			pcc->swing_buffer--;
		else
			pcc->amplifier++;
	}
	else
	{
		pcc->swing_buffer = min(pcc->swing_buffer + 1, PCC_MAX_SWING_BUFFER);
		pcc->amplifier = 1;
		//pcc->change_bound = PCC_MIN_CHANGE_BOUND;
	}

	if (decision != PCC_RATE_STAY) {
		for (i = 0; i < DECISION_HISTORY_SIZE - 1; i++) {
			if (pcc->decision_history[i+1] == decision) {
				same_decisions++;
			}
			pcc->decision_history[i] = pcc->decision_history[i+1];
		}
		pcc->decision_history[DECISION_HISTORY_SIZE-1] = decision;
		if (same_decisions > DECISION_HISTORY_SIZE / 2){
			//pcc->amplifier = same_decisions - DECISION_HISTORY_SIZE / 2;
		}
	}
	DBG_PRINT(KERN_INFO "%hhu: amplifier is %hhd decision is %d same decisions is %d\n", pcc->id, pcc->amplifier, decision, same_decisions);
}

/* Bound any rate change as a proportion of the current rate, so large gradients
 * don't drasitcally change sending rate.
 */
static s64 pcc_apply_change_bound(struct pcc_data *pcc, s64 step)
{
	s32 step_sign;
	s64 change_ratio;
	s64 total_rate = pcc->rate + pcc->others_rate;
	if (pcc->rate == 0)
		return step;

	step_sign = step > 0 ? 1 : -1;
	step *= step_sign;
	change_ratio = (PCC_SCALE * step) / total_rate;
//	if (step_sign > 0) {
		if (change_ratio > pcc->change_bound)
		{
			step = (total_rate * pcc->change_bound) / PCC_SCALE;
			DBG_PRINT("%hhu bound: %u rate %lld step %lld\n",pcc->id, pcc->change_bound, (pcc->rate * 8) / (1024 * 1024), step * step_sign);
			pcc->change_bound += PCC_CHANGE_BOUND_STEP;
		}
		else if (change_ratio < pcc->change_bound - PCC_CHANGE_BOUND_STEP)
		{
			if (pcc->change_bound >= PCC_MIN_CHANGE_BOUND + PCC_CHANGE_BOUND_STEP)
				pcc->change_bound -= PCC_CHANGE_BOUND_STEP;
			//pcc->change_bound = PCC_MIN_CHANGE_BOUND;
		}

	change_ratio = (PCC_SCALE * step) / pcc->rate;
	/*if (change_ratio > 500) {
		if (pcc->change_bound >= PCC_MIN_CHANGE_BOUND + PCC_CHANGE_BOUND_STEP)
			pcc->change_bound -= PCC_CHANGE_BOUND_STEP;
		DBG_PRINT("%hhu bound: step too big for current subflow. ratio %lld %u rate %lld step %lld\n",pcc->id, change_ratio, pcc->change_bound, (pcc->rate * 8) / (1024 * 1024), step * step_sign);
		step = pcc->rate / 2;	
	}
	*/

	if (step > pcc->rate) {
		DBG_PRINT("%hhu bound: step bigger than rate. ratio %lld %u rate %lld step %lld\n", pcc->id, change_ratio, pcc->change_bound, (pcc->rate * 8) / (1024 * 1024), step * step_sign);
		step = pcc->rate / 2;
	}

	return step_sign * step;
}

static s64 pcc_convert_gradient_to_step(struct pcc_data *pcc, s64 grad)
{
	s64 step;
	s64 total_rate = pcc->rate + pcc->others_rate;
	s64 sign = 0;
	s64 allowed_change = PCC_MIN_CHANGE_BOUND;
	enum PCC_DECISION decision = PCC_RATE_STAY;

	if (grad == 0) {
		return PCC_MIN_RATE_CHANGE;
	}
	
	step = grad * PCC_GRAD_TO_RATE_FACTOR / 2;  /* gradient ascent */
	//step *= 1000000LL;
	if (grad > 0) {
		sign = 1;
		decision = PCC_RATE_UP;
	} else if (grad < 0) {
		sign = -1;
		decision = PCC_RATE_DOWN;
	}

	if (pcc->last_decision != decision) {
		pcc->amplifier = 0;
		pcc->change_bound = 0;
		if (pcc->swing_buffer < PCC_MAX_SWING_BUFFER) {
			pcc->swing_buffer++;
		}
	}
	/*
	if (pcc->amplifier < 4) {
		step *= (1 + pcc->amplifier / 2);
	} else if (pcc->amplifier < 12) {
		step *= (pcc->amplifier - 2);
	} else if (pcc->amplifier < 18) {
		step *= (2 * pcc->amplifier) - 14;
	} else {
		step *= (4 * pcc->amplifier) - 50;
	}
	*/
	step *= 1 + pcc->amplifier;
	if (pcc->last_decision == decision) {
		if (pcc->swing_buffer == 0) {
			//if (pcc->amplifier < 3) {
				pcc->amplifier += 2;
			//} else {
			//	pcc->amplifier += 2;
			//}
		} else {
			pcc->swing_buffer--;
		}
	}

	allowed_change += pcc->change_bound * PCC_CHANGE_BOUND_STEP;
	if ((PCC_SCALE * (sign * step)) / total_rate > allowed_change) {
		pcc->change_bound++;
		printk(KERN_INFO "%hhu: bound: step is %lld change is %lld allowed_change is %lld, changing to %lld\n", pcc->id, step, (PCC_SCALE * (sign * step)) / total_rate, allowed_change, allowed_change * total_rate * sign / PCC_SCALE);
		step = allowed_change * total_rate * sign / PCC_SCALE; 
	} else if (pcc->change_bound > 0) {
		pcc->change_bound--;
	}

	//step /= PCC_SCALE;

	if (step * sign < PCC_MIN_RATE_CHANGE) {
		printk(KERN_INFO "%hhu: step is %lld, changing to min step\n", pcc->id, step);
		step = sign * PCC_MIN_RATE_CHANGE;
	}

	if (step * sign > pcc->rate / 2) {
		printk(KERN_INFO "%hhu: step is %lld bigger than rate, changing to %lld\n", pcc->id, step,sign * pcc->rate / 2);
		step = sign * pcc->rate / 2;
	}
	if (pcc->last_decision != decision) {
		pcc->amplifier = 0;
		pcc->change_bound = 0;

	} 
	
	DBG_PRINT(KERN_INFO "%hhu grad: grad %lld step %lld amp %d\n",
		   pcc->id, grad, step, pcc->amplifier);
	return step;
}

static void pcc_decide(struct pcc_data *pcc, struct sock *sk)
{
	struct pcc_interval *interval;
	s64 rate_change, grad;
	s64 new_rate;
	s64 avg_thput = 0;
	s64 max_thput = 0;
	int i;
	enum PCC_DECISION decision;
	char rand;
	s64 rate_sign = 0;
	int emergency_brake = 0;

	for (i = 0; i < PCC_INTERVALS; i++)
	{
		interval = &pcc->intervals[i];
		pcc_calc_utility_vivace(pcc, interval, sk);
		avg_thput += interval->throughput;
		if (max_thput < interval->throughput) {
			max_thput = interval->throughput;
		}
		if (pcc->intervals[i].loss_ratio > EMERGENCY_BRAKE_RATIO && pcc->intervals[i].packets_sent > 100)
			emergency_brake++;
	}
	avg_thput /= PCC_INTERVALS;

	grad = pcc_decide_rate(pcc);
	if (grad == 0)
	{
		DBG_PRINT(KERN_INFO "pcc_decide: grad is 0\n");
		rate_change = 0;
		//pcc->rate += pcc->rate / 200;
	}	
	else {
		rate_change = pcc_convert_gradient_to_step(pcc, grad);
	}

	if (emergency_brake > 2) {
		rate_change = -pcc->rate / 2;
		DBG_PRINT(KERN_INFO "%hhu pcc_decide: emergency brake!\n",pcc->id);
	}

	//if (avg_thput < (4 * pcc->rate) / 5)
	//	rate_change = -(pcc->rate + pcc->others_rate) / 100;
	//rate_change *= 2;
	DBG_PRINT(KERN_INFO "%hhu pcc_decide: rate_change is %lld (%lld), grad is %lld\n",pcc->id, rate_change,(rate_change * 8) / (1024 * 1024), grad);
	
	new_rate = rate_change + pcc->rate;
	decision = pcc_get_decision(pcc, new_rate);
	//pcc_update_step_params(pcc, rate_change, decision);
	pcc->last_decision = decision;
	pcc->last_rate = pcc->rate;
	if (rate_change > 0)
		rate_sign = 1;
	else if (rate_change < 0)
		rate_sign = -1;
	if (rate_change * rate_sign > pcc->rate / 2) {
		printk("%hhu bound: step too big for current subflow. rate %lld step %lld\n",pcc->id, pcc->rate, rate_change);
		rate_change = rate_sign * pcc->rate / 2 ;
	}
	new_rate = pcc->rate + rate_change;
	
	if (new_rate < PCC_RATE_MIN) {
		new_rate = PCC_RATE_MIN;
	}
	if (new_rate != pcc->rate)
	{
		DBG_PRINT(KERN_INFO "%hhu decide: nrate dir: %d rate: %llu grad: %lld step: %lld dcount: (%hhu)\n",
			   pcc->id, pcc->rate < new_rate, (new_rate * 8) / (1024 * 1024), grad, rate_change,
			   pcc->decisions_count);
		pcc->rate = new_rate;
		pcc_setup_intervals_moving(pcc);
		pcc->moving = true;
		pcc->decisions_count = 0;
		//pcc_setup_intervals_probing(sk, pcc);
	}
	else
	{
		DBG_PRINT(KERN_INFO "%hhu decide: stay %lld (%hhu)\n", pcc->id,
			   pcc->rate, pcc->decisions_count);
		//pcc->decisions_count++;
		pcc_setup_intervals_probing(sk, pcc);
	} 
 
	//pcc_setup_intervals_probing(sk, pcc);
	get_random_bytes(&rand, 1);
	//if (rand & 1)
		pcc->advertised_rate = pcc->rate;
	start_interval(sk, pcc);
}

/* Choose up/down rate changes based on utility gradient */
static u32 pcc_decide_rate_moving(struct sock *sk, struct pcc_data *pcc)
{
	struct pcc_interval *interval = &pcc->intervals[0];
	s64 utility, prev_utility, grad;
	s64 new_rate, rate_change;

	prev_utility = interval->utility;
	pcc_calc_utility_vivace(pcc, interval, sk);
	utility = interval->utility;


	grad = pcc_calc_util_grad(pcc->rate, utility, pcc->last_rate, prev_utility);
	if (grad == 0) {
		return pcc->rate;
	}
	rate_change = pcc_convert_gradient_to_step(pcc, grad);
	new_rate = pcc->rate + rate_change;
	
	new_rate = pcc->rate + rate_change;

	DBG_PRINT(KERN_INFO "%hhu mv: pr %lld pu %lld nr %lld nu %lld step %lld (%lld)\n",
		   pcc->id, (pcc->last_rate * 8) / (1024 * 1024), prev_utility, (pcc->rate * 8) / (1024 * 1024), utility, rate_change, (rate_change * 8) / (1024 * 1024));
	//pcc->others_rate = mpcc_get_others_rate(sk);
	//pcc_calc_utility_vivace(pcc, interval, sk);
	pcc->prev_loss_rate = interval->loss_ratio;
	return new_rate;
}

/* Choose new direction and update state from the moving state.*/
static void pcc_decide_moving(struct sock *sk, struct pcc_data *pcc)
{
	s64 new_rate = pcc_decide_rate_moving(sk, pcc);
	enum PCC_DECISION decision = pcc_get_decision(pcc, new_rate);
	enum PCC_DECISION last_decision = pcc->last_decision;
	pcc->last_rate = pcc->rate;
	DBG_PRINT(KERN_INFO "%hhu moving: new rate %lld (%hhu) old rate %lld, decision %d las decision %d\n",
		   pcc->id, (new_rate * 8) / (1024 * 1024),
		   pcc->decisions_count, (pcc->last_rate * 8) / (1024 * 1024), decision, last_decision);
	//pcc->advertised_rate = pcc->rate;
	//pcc->rate = new_rate;
	if (pcc->intervals[0].loss_ratio > EMERGENCY_BRAKE_RATIO && pcc->intervals[0].packets_sent > 100) {
		pcc->rate /= 2;
		pcc_setup_intervals_probing(sk, pcc);
		start_interval(sk, pcc);
		return;
	}
	if (decision != last_decision)
	{

#ifdef USE_PROBING
		pcc->moving = false;
		pcc_setup_intervals_probing(sk, pcc);
#else
		pcc->rate = new_rate;
		pcc_setup_intervals_moving(pcc);
#endif
	}
	else
	{
		pcc->rate = new_rate;
		pcc_setup_intervals_moving(pcc);
	}

	start_interval(sk, pcc);
}

/* Double target rate until the link utility doesn't increase accordingly. Then,
 * cut the rate in half and change to the gradient ascent moving stage.
 */
static void pcc_decide_slow_start(struct sock *sk, struct pcc_data *pcc)
{
	struct pcc_interval *interval = &pcc->intervals[0];
	s64 utility, prev_utility, adjust_utility, prev_adjust_utility, tmp_rate;
	s64 extra_rate;
	s64 throughput_diff = 0;

	prev_utility = interval->utility;
	pcc_calc_utility_vivace(pcc, interval, sk);
	utility = interval->utility;

	/* The new utiltiy should be at least 75% of the expected utility given
	 * a significant increase. If the utility isn't as high as expected, then
	 * we end slow start.
	 */
	adjust_utility = utility * (utility > 0 ? 1000 : 750) / pcc->rate;
	prev_adjust_utility = prev_utility * (prev_utility > 0 ? 750 : 1000) /
						  pcc->last_rate;
	throughput_diff = interval->throughput;
	throughput_diff *= PCC_SCALE;
	throughput_diff /= interval->rate;

	DBG_PRINT(KERN_INFO "%hhu: start mode: r %lld u %lld pr %lld pu %lld\n",
		   pcc->id, (pcc->rate * 8) / (1024 * 1024), utility, (pcc->last_rate * 8) / (1024 * 1024), prev_utility);
	//if (adjust_utility > prev_adjust_utility) {
	if (utility > prev_utility && throughput_diff > 900)
	{
		pcc->last_rate = pcc->rate;
		extra_rate = pcc->intervals[0].delivered *
					 tcp_sk(sk)->mss_cache;
		extra_rate = min(extra_rate, pcc->rate / 2);

		pcc->rate += pcc->rate; //extra_rate;
		interval->utility = utility;
		interval->rate = pcc->rate;
		pcc->send_index = 0;
		pcc->recive_index = 0;
		pcc->wait = false;
		pcc->slow_start_attempts = PCC_SLOW_START_ATTEMPTS;
	}
	else if (pcc->slow_start_attempts > 0) {
		DBG_PRINT(KERN_INFO "%hhu: start mode: throughput_diff %lld rate %d thput %u\n", pcc->id, throughput_diff, interval->rate, interval->throughput);
		interval->utility = prev_utility;
		pcc->slow_start_attempts--;
		pcc->send_index = 0;
		pcc->recive_index = 0;
		pcc->wait = false;
	}
	else
	{
		tmp_rate = pcc->last_rate;
		pcc->last_rate = pcc->rate;
		pcc->rate = tmp_rate;
		pcc->start_mode = false;
		DBG_PRINT(KERN_INFO "%hhu: start mode ended, next rate is %lld\n", pcc->id, (pcc->rate * 8) / (1024 * 1024));

#ifdef USE_PROBING
		pcc_setup_intervals_probing(sk, pcc);
#else
		pcc->moving = true;
		pcc_setup_intervals_moving(pcc);
#endif
	}
	start_interval(sk, pcc);
}

/**************************
 * intervals & sample:
 * was started, was ended,
 * find interval per sample
 * ************************/

/* Have we sent all the data we need to for this interval? Must have at least
 * the minimum number of packets and should have sent 1 RTT worth of data.
 */
bool send_interval_ended(struct pcc_interval *interval, struct tcp_sock *tsk,
						 struct pcc_data *pcc)
{
	u32 packets_sent = (interval->end_seq - interval->start_seq) / tsk->mss_cache;
	u32 duration = tsk->srtt_us >> 3;
	if (pcc->start_mode)
		duration *= 2;

	if (pcc->wait) {
		return false;
	}
	if (tsk->tcp_mstamp - interval->send_start < interval->send_end_time) {
		return false;
	}

	if (packets_sent < PCC_INTERVAL_MIN_PACKETS)
		return false;

	DBG_PRINT(KERN_INFO "%hhu interval %hhu finished sending. sent sequences %u-%u packets: %u-%u\n", pcc->id, pcc->send_index, interval->start_seq, interval->end_seq, interval->packets_sent_base, tsk->data_segs_out);
	interval->send_ended = true;
	return true;
}

/* Have we accounted for (acked or lost) enough of the packets that we sent to
 * calculate summary statistics?
 */
bool recive_interval_ended(struct pcc_interval *interval,
						   struct tcp_sock *tsk, struct pcc_data *pcc)
{
	return interval->send_ended && after(interval->last_known_seq, interval->end_seq);
}

/* Start the next interval's sending stage. If there is no interval scheduled
 * to send (we have enough for probing, or we are in slow start or moving),
 * then we will be maintaining our rate while we wait for acks.
 */
static void start_next_send_interval(struct sock *sk, struct pcc_data *pcc)
{
	pcc->send_index++;
	if (pcc->send_index == PCC_INTERVALS || pcc->start_mode || pcc->moving)
	{
		pcc->wait = true;
	}

	start_interval(sk, pcc);
}

/* Update the receiving time window and the number of packets lost/delivered
 * based on socket statistics.
 */
static void update_current_interval_sequences(struct sock* sk, struct pcc_interval* interval)
{
	interval->end_seq = tcp_sk(sk)->snd_nxt;
}

static void update_interval_sack(struct sock* sk, struct pcc_data *pcc)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int i,j;
	struct tcp_sack_block sack_cache[4];

	//sort received sacks according to sequence in increasing order
	if (tp->sacked_out) {
		memcpy(sack_cache, tp->recv_sack_cache, sizeof(sack_cache));
		for (i = 0; i < 4; i++) {
			for (j = i+1; j < 4; j++) {
				if (after(sack_cache[i].start_seq, sack_cache[j].start_seq)) {
					u32 tmp = sack_cache[i].start_seq;
					sack_cache[i].start_seq = sack_cache[j].start_seq;
					sack_cache[j].start_seq = tmp;

					tmp = sack_cache[i].end_seq;
					sack_cache[i].end_seq = sack_cache[j].end_seq;
					sack_cache[j].end_seq = tmp;
				}
			}
		}
	}
	
	//for all active intervals check if cumulative acks changed the last known seq, or if the sacks did
	for (i = 0; i < PCC_INTERVALS; i++) {
		struct pcc_interval *loop_mon = pcc->intervals + i;
		u32 current_interval_last_known = loop_mon->last_known_seq;

		//set the last known sequence to the last cumulative ack if it is better than the last known seq
		if (after(tp->snd_una, loop_mon->last_known_seq)) {
			loop_mon->last_known_seq = tp->snd_una;
		}

		//there are sacks
		if (tp->sacked_out) {
			for (j = 0; j < 4; j++) {
				//if the sack doesn't bring any new information, check the next one
				if (!before(loop_mon->last_known_seq, loop_mon->end_seq)) {
					continue;
				}

				//mark the hole as lost bytes in this monitor interval
				if (sack_cache[j].start_seq != 0 && sack_cache[j].end_seq != 0) {
					if (before(loop_mon->last_known_seq, sack_cache[j].start_seq)) {
						if (before(sack_cache[j].start_seq, loop_mon->end_seq)) {
							s32 lost = sack_cache[j].start_seq - loop_mon->last_known_seq;
							if (lost < 0) {
								DBG_PRINT("bug. lost < 0 line %d sack %u-%u mon %u-%u last_known %u\n", __LINE__, sack_cache[j].start_seq, sack_cache[j].end_seq, loop_mon->start_seq, loop_mon->end_seq, loop_mon->last_known_seq);
							}
							
							loop_mon->bytes_lost += lost;
						} else {
							s32 lost = loop_mon->end_seq - loop_mon->last_known_seq;
							if (lost < 0) {
								DBG_PRINT("bug. lost < 0 line %d sack %u-%u mon %u-%u last_known %u\n", __LINE__, sack_cache[j].start_seq, sack_cache[j].end_seq, loop_mon->start_seq, loop_mon->end_seq, loop_mon->last_known_seq);
							}
							loop_mon->bytes_lost += lost;
						}

					}
					//update the last known seq if it was changed
					if (after(sack_cache[j].end_seq, loop_mon->last_known_seq)) {
						loop_mon->last_known_seq = sack_cache[j].end_seq;
					}
				}
			}
		}
        if (current_interval_last_known == loop_mon->start_seq && loop_mon->last_known_seq != current_interval_last_known) {
		DBG_PRINT(KERN_INFO "%hhu: setting start rtt of interval %d\n", pcc->id, i);
            loop_mon->recv_start = tcp_sk(sk)->tcp_mstamp;
            loop_mon->start_rtt = tcp_sk(sk)->srtt_us >> 3;
            loop_mon->end_rtt = tcp_sk(sk)->srtt_us >> 3;
        }
        if (before(current_interval_last_known, loop_mon->end_seq) && !after(loop_mon->last_known_seq, loop_mon->end_seq) && !tp->is_cwnd_limited) {
            loop_mon->recv_end = tcp_sk(sk)->tcp_mstamp;
            loop_mon->end_rtt = tcp_sk(sk)->srtt_us >> 3;
        }
	if (tcp_sk(sk)->tcp_mstamp > loop_mon->send_start + loop_mon->timeout && before(loop_mon->last_known_seq, loop_mon->end_seq)) {
		//DBG_PRINT(KERN_INFO "interval timeout\n");
		//loop_mon->bytes_lost += loop_mon->end_seq - loop_mon->last_known_seq;
		//loop_mon->last_known_seq = loop_mon->end_seq;
	}

	}

}
static void
pcc_update_interval(struct pcc_interval *interval, struct pcc_data *pcc,
					struct sock *sk)
{
	//	if (pcc_interval_in_ignore(interval))
	//		return;

	interval->recv_end = tcp_sk(sk)->tcp_mstamp;
	interval->end_rtt = tcp_sk(sk)->srtt_us >> 3;
	if (interval->lost + interval->delivered == 0)
	{
		DBG_PRINT(KERN_INFO "%hhu: interval first recv seq: %u\n", pcc->id, tcp_sk(sk)->snd_una);
		interval->recv_start = tcp_sk(sk)->tcp_mstamp;
		interval->start_rtt = tcp_sk(sk)->srtt_us >> 3;
	}

	interval->lost += tcp_sk(sk)->lost - pcc->lost_base;
	interval->delivered += tcp_sk(sk)->delivered - pcc->delivered_base;
}

/* Updates the PCC model */
static void pcc_process(struct sock *sk)
{
	struct pcc_data *pcc = inet_csk_ca(sk);
	struct tcp_sock *tsk = tcp_sk(sk);
	struct pcc_interval *interval;
	int index;

	if (!pcc_valid(pcc))
		return;

	//if (pcc->start_mode)
	//	return;

	pcc_set_cwnd(sk);
	if (!pcc->wait)
	{
		interval = &pcc->intervals[pcc->send_index];
		update_current_interval_sequences(sk, interval);
		if (send_interval_ended(interval, tsk, pcc))
		{
			interval->send_end = tcp_sk(sk)->tcp_mstamp;
			interval->packets_ended = tsk->data_segs_out;
			start_next_send_interval(sk, pcc);
		}
	}
	update_interval_sack(sk, pcc);

	index = pcc->recive_index;
	interval = &pcc->intervals[index];
	if (recive_interval_ended(interval, tsk, pcc))
	{
		pcc->recive_index++;
		if (pcc->start_mode)
			pcc_decide_slow_start(sk, pcc);
		else if (pcc->moving)
			pcc_decide_moving(sk, pcc);
		else if (pcc->recive_index == PCC_INTERVALS)
			pcc_decide(pcc, sk);
	}
}

static void pcc_process_sample(struct sock *sk, const struct rate_sample *rs)
{
	pcc_process(sk);
}

static void pcc_init(struct sock *sk)
{
	struct pcc_data *pcc = inet_csk_ca(sk);

	pcc->intervals = kzalloc(sizeof(struct pcc_interval) * PCC_INTERVALS * 2,
							 GFP_KERNEL);
	if (!pcc->intervals)
	{
		DBG_PRINT(KERN_INFO "init fails\n");
		return;
	}
	DBG_PRINT(KERN_INFO "in init, snd next is %u\n", tcp_sk(sk)->snd_nxt);

	id++;
	pcc->id = id;
	pcc->amplifier = PCC_AMP_MIN;
	pcc->change_bound = PCC_MIN_CHANGE_BOUND;
	pcc->decision_history = kzalloc(sizeof(enum PCC_DECISION) * DECISION_HISTORY_SIZE, GFP_KERNEL);
	//pcc->rate = 10 * 1024 * 1024 / 8;
	pcc->rate = 500000;
	pcc->advertised_rate = pcc->rate;
	pcc->last_rate = pcc->rate;
	tcp_sk(sk)->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	//tcp_sk(sk)->snd_ssthresh = 10000;
	pcc->start_mode = true;
	pcc->moving = false;
	pcc->intervals[0].utility = S64_MIN;
	pcc->others_rate = 0;
	pcc->decisions_count = 1;
	pcc->slow_start_attempts = PCC_SLOW_START_ATTEMPTS;
	//sk->sk_pacing_rate = 400 * 1024 * 1024 / 8;
	//tcp_sk(sk)->snd_cwnd = 4;

	pcc_setup_intervals_probing(sk, pcc);
	start_interval(sk, pcc);
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
	//cmpxchg(&sk->sk_pacing_status, SK_PACING_NEEDED, SK_PACING_NONE);
}

static void pcc_release(struct sock *sk)
{
	struct pcc_data *pcc = inet_csk_ca(sk);

	kfree(pcc->intervals);
	kfree(pcc->decision_history);
}

/* PCC does not need to undo the cwnd since it does not
 * always reduce cwnd on losses (see pcc_main()). Keep it for now.
 */
static u32 pcc_undo_cwnd(struct sock *sk)
{
	DBG_PRINT("in undo cwnd\n");
	/*
	struct pcc_data *pcc = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	if (pcc->start_mode) {
		pcc->rate /= 2;
		printk(KERN_INFO "out of slow start with cwnd %u and rate %llu next seq %u\n", tp->snd_cwnd, pcc->rate, tp->snd_nxt);
		pcc_setup_intervals_probing(sk, pcc);
		start_interval(sk, pcc);
		pcc->start_mode = false;
		cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
	}
	*/
	return tcp_sk(sk)->snd_cwnd;
}

static u32 pcc_ssthresh(struct sock *sk)
{
	return TCP_INFINITE_SSTHRESH; /* PCC does not use ssthresh */
}

static void pcc_set_state(struct sock *sk, u8 new_state)
{
	struct pcc_data *pcc = inet_csk_ca(sk);

	if (!pcc_valid(pcc))
		return;

}

static void pcc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct pcc_data* pcc = inet_csk_ca(sk);
	//struct tcp_sock *tp = tcp_sk(sk);
	DBG_PRINT("in pcc cong avoid\n");

	if (pcc->start_mode) {
		DBG_PRINT("in cong avoid\n");
		//tcp_reno_cong_avoid(sk, ack, acked);
		//tcp_slow_start(tp, acked);
	}
}

static void pcc_pkts_acked(struct sock *sk, const struct ack_sample *acks)
{
	//struct pcc_data *pcc = inet_csk_ca(sk);
	//struct tcp_sock *tp = tcp_sk(sk);
	//u32 rate;
	//printk("in pcc pkts acked start: %d %d %u %u\n", pcc->start_mode, tp->snd_cwnd, sk->sk_pacing_rate, pcc->rate);

	//if (!pcc->start_mode)
		pcc_process(sk);
	/*else {
		//tp->snd_cwnd += acks->pkts_acked;
		tcp_slow_start(tp, acks->pkts_acked);
		rate = tp->snd_cwnd;
		if (rate < pcc->rate) {
			pcc->rate *= tp->mss_cache;
			pcc->rate /= 2;
			pcc->rate *= USEC_PER_SEC;
			pcc->rate /= (tp->srtt_us >> 3);
			pcc->start_mode = false;
			pcc_setup_intervals_probing(sk, pcc);
			start_interval(sk, pcc);
			cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
		} else {
			pcc->rate = rate;
			//sk->sk_pacing_rate = rate * tp->mss_cache * USEC_PER_SEC / (tp->srtt_us >> 3);
		}
	}
	*/
}

static void pcc_ack_event(struct sock *sk, u32 flags)
{
	struct pcc_data *pcc = inet_csk_ca(sk);
	//struct tcp_sock *tp = tcp_sk(sk);
	if (!pcc->start_mode) {
		pcc_process(sk);
	}
}

static void pcc_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct pcc_data *pcc = inet_csk_ca(sk);
	DBG_PRINT("%hhu cwnd_event: %d cwnd %d rate %u (%u)\n", pcc->id, event, tcp_sk(sk)->snd_cwnd, sk->sk_pacing_rate, TO_MPBPS(sk->sk_pacing_rate));
}

static struct tcp_congestion_ops tcp_pcc_cong_ops __read_mostly = {
	.flags = TCP_CONG_NON_RESTRICTED,
	.name = "pcc",
	.owner = THIS_MODULE,
	.init = pcc_init,
	.release = pcc_release,
	.cong_control = pcc_process_sample,
	/* Keep the windows static */
	.undo_cwnd = pcc_undo_cwnd,
	/* Slow start threshold will not exist */
	.ssthresh = pcc_ssthresh,
	.set_state = pcc_set_state,
	.cong_avoid = pcc_cong_avoid,
	.pkts_acked = pcc_pkts_acked,
	.in_ack_event = pcc_ack_event,
	.cwnd_event = pcc_cwnd_event,
};

/* Kernel module section */

static int __init pcc_register(void)
{
	BUILD_BUG_ON(sizeof(struct pcc_data) > ICSK_CA_PRIV_SIZE);
	DBG_PRINT(KERN_INFO "pcc init reg\n");
	return tcp_register_congestion_control(&tcp_pcc_cong_ops);
}

static void __exit pcc_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_pcc_cong_ops);
}

module_init(pcc_register);
module_exit(pcc_unregister);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP PCC (Performance-oriented Congestion Control)");
