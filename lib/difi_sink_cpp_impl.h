// -*- c++ -*-
// Copyright (c) Microsoft Corporation.
// Licensed under the GNU General Public License v3.0 or later.
// See License.txt in the project root for license information.



#ifndef INCLUDED_DIFI_SINK_CPP_IMPL_H
#define INCLUDED_DIFI_SINK_CPP_IMPL_H

#include <difi/difi_sink_cpp.h>
#include <difi/difi_common.h>



namespace gr {
  namespace difi {

  class tcp_client;
  class udp_socket;

    template <class T>
    class difi_sink_cpp_impl : public difi_sink_cpp<T>
    {
     private:
        void pack_u64(unsigned char * start, u_int64_t val)
        {
          val = htobe64(val);
          memcpy(start, &val, sizeof(val));
        }
        void pack_u32(unsigned char * start, u_int32_t val)
        {
          val = htonl(val);
          memcpy(start, &val, sizeof(val));
        }

        void pack_u64(int8_t * start, u_int64_t val)
        {
          val = htobe64(val);
          memcpy(start, &val, sizeof(val));
        }
        void pack_u32(int8_t * start, u_int32_t val)
        {
          val = htonl(val);
          memcpy(start, &val, sizeof(val));
        }

        void process_tags(int noutput_items);
        void pack_T(T val);
        // Nik Ansell: Function to troubleshoot float to fixed point to hex conversion
        std::string int64ToHex(u_int64_t input);

        std::vector<int8_t> pack_data();
        void send_context();
        std::tuple<u_int32_t, u_int64_t> add_frac_full();

        int d_stream_number;
        int d_reference_point;
        u_int32_t d_full_samp;
        long d_oui;
        int d_packet_class;
        pmt::pmt_t d_context_key;
        pmt::pmt_t d_pkt_n_key;
        pmt::pmt_t d_static_change_key;
        u_int32_t d_full;
        u_int64_t d_frac;
        u_int32_t d_data_len;
        u_int8_t d_pkt_n;
        int32_t d_static_bits;
        std::vector<int8_t> d_raw;
        std::vector<u_int8_t> d_context_raw;
        std::vector<int8_t> d_out_buf;
        double d_time_adj;
        u_int64_t d_pcks_since_last_reference;
        int d_current_buff_idx;
        bool d_is_paired_mode;
        u_int64_t d_contex_packet_interval;
        u_int64_t d_packet_count;
        u_int32_t d_context_packet_count;
        long d_last_context_packet_sent_packet_number;
        u_int16_t d_context_packet_size;
        u_int32_t d_context_static_bits;
        u_int32_t d_unpack_idx_size;
        u_int32_t d_samples_per_packet;
        int d_scaling_mode;
        float d_gain;
        gr_complex d_offset;
        float d_max_iq;
        float d_min_iq;
        u_int64_t d_bandwidth_hz;
        uint32_t d_tx_gain;
        u_int64_t d_rf_ref_hz;
        uint32_t d_ref_level;
        tcp_client* p_tcpsocket;
        udp_socket* p_udpsocket;

     public:
      difi_sink_cpp_impl(u_int32_t reference_time_full, u_int64_t reference_time_frac, std::string ip_addr, uint32_t port, uint8_t socket_type, bool mode,
                        uint32_t samples_per_packet, int stream_number, int reference_point, u_int64_t samp_rate, int packet_class,
                        int oui, int context_interval, int context_pack_size, int bit_depth, int scaling, float gain, gr_complex offset, float max_iq, float min_iq, u_int64_t bandwidth_hz,
                        uint32_t tx_gain, u_int64_t rf_ref_hz, uint32_t ref_level);
      ~difi_sink_cpp_impl();

      // Where all the action really happens
      int work(
              int noutput_items,
              gr_vector_const_void_star &input_items,
              gr_vector_void_star &output_items
      );
    };

  } // namespace difi
} // namespace gr

#endif /* INCLUDED_DIFI_SINK_CPP_IMPL_H */

