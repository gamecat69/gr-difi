// -*- c++ -*-
// Copyright (c) Microsoft Corporation.
// Licensed under the GNU General Public License v3.0 or later.
// See License.txt in the project root for license information.

#include <gnuradio/io_signature.h>
#include "difi_sink_cpp_impl.h"

#include "tcp_client.h"
#include "udp_socket.h"

// Nik Ansell: used to get initial timestamp
#include <ctime>

namespace gr {
  namespace difi {

    template <class T>
    typename difi_sink_cpp<T>::sptr
    difi_sink_cpp<T>::make(u_int32_t reference_time_full, u_int64_t reference_time_frac, std::string ip_addr, uint32_t port, uint8_t socket_type,
                          bool mode, uint32_t samples_per_packet, int stream_number, int reference_point, u_int64_t samp_rate,
                          int packet_class, int oui, int context_interval, int context_pack_size, int bit_depth,
                          int scaling, float gain, gr_complex offset, float max_iq, float min_iq)
    {
      return gnuradio::make_block_sptr<difi_sink_cpp_impl<T>>(reference_time_full, reference_time_frac, ip_addr, port, socket_type, mode,
                                                              samples_per_packet, stream_number, reference_point, samp_rate, packet_class, oui, context_interval, context_pack_size, bit_depth,
                                                              scaling, gain, offset, max_iq, min_iq);
    }

    template <class T>
    difi_sink_cpp_impl<T>::difi_sink_cpp_impl(u_int32_t reference_time_full, u_int64_t reference_time_frac, std::string ip_addr,
                                              uint32_t port, uint8_t socket_type, bool mode, uint32_t samples_per_packet, int stream_number, int reference_point,
                                              u_int64_t samp_rate, int packet_class, int oui, int context_interval, int context_pack_size, int bit_depth,
                                              int scaling, float gain, gr_complex offset, float max_iq, float min_iq)
      : gr::sync_block("difi_sink_cpp_impl",
              gr::io_signature::make(1, 1, sizeof(T)),
              gr::io_signature::make(0, 0, 0)),
              d_stream_number(int(stream_number)),
              d_reference_point(reference_point),
              d_full_samp(samp_rate),
              d_oui(oui),
              d_packet_class(packet_class),
              d_pkt_n(0),
              d_current_buff_idx(0),
              d_pcks_since_last_reference(0),
              d_is_paired_mode(mode),
              d_packet_count(0),
              d_context_packet_count(0),
              d_context_packet_size(context_pack_size),
              d_contex_packet_interval(context_interval),
              p_tcpsocket(0),
              p_udpsocket(0)

    {
      socket_type = (socket_type == 1) ?  SOCK_STREAM : SOCK_DGRAM;
      // Nik Ansell: Show connection message in logs for troubleshooting
      GR_LOG_INFO(this->d_logger, "Connecting to:" + ip_addr + ":" + std::to_string(port));
      if(socket_type == SOCK_DGRAM)
      {
        p_udpsocket = new udp_socket(ip_addr,port,false);
      }
      else
      {
        p_tcpsocket = new tcp_client(ip_addr,port);
      }

      if (samples_per_packet < 2)
      {
        GR_LOG_ERROR(this->d_logger, "samples per packet cannot be less than 2, (to ensure one 32 bit word is filled)");
        throw std::runtime_error("samples per packet cannot be less than 2, (to ensure one 32 bit word is filled)");
      }
      d_context_key = pmt::intern("context");
      d_pkt_n_key = pmt::intern("pck_n");
      d_static_change_key = pmt::intern("static_change");
      //  Nik Ansell: Add current time to reference time
      d_full = reference_time_full + std::time(nullptr);

      d_frac = reference_time_frac;
      // Nik Ansell: Change time to GPS time (10) from Other (11)
      //d_static_bits = 0x18e00000; // default, will change after first packet else, this is the DIFI standard first 12 bits
      d_static_bits = 0x18a00000; // default, will change after first packet else, this is the DIFI standard first 12 bits
      // Nik Ansell: Change header to include time stamp types
      // d_context_static_bits = 0x49000000;// default, will change after first packet else, this is the DIFI standard first 8 bits
      d_context_static_bits = 0x49a00000;// default, will change after first packet else, this is the DIFI standard first 8 bits
      d_unpack_idx_size = bit_depth == 8 ? 1 : 2;
      d_samples_per_packet = samples_per_packet;
      d_time_adj = (double)d_samples_per_packet / samp_rate;
      d_data_len = samples_per_packet * d_unpack_idx_size * 2;
      u_int32_t tmp_header_data = d_static_bits ^ d_pkt_n << 16 ^ (d_data_len / 4);


      // Nik Ansell: Manualyl override the context packet size for now, based on new context packet encoding format
      context_pack_size = 84;

      u_int32_t tmp_header_context = d_context_static_bits ^ d_context_packet_count << 16 ^ (context_pack_size  / 4);
      u_int64_t class_id = d_oui << 32 ^ d_packet_class;
      d_raw.resize(difi::DIFI_HEADER_SIZE);
      pack_u32(&d_raw[0], tmp_header_data);
      pack_u32(&d_raw[4], d_stream_number);
      int idx = 0;
      pack_u64(&d_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], class_id);
      pack_u32(&d_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0);
      pack_u64(&d_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0);

      //pack context for standalone mode only
      d_context_raw.resize(context_pack_size);
      pack_u32(&d_context_raw[0], tmp_header_context);
      pack_u32(&d_context_raw[4], d_stream_number);
      idx = 0;
      pack_u64(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], class_id);
      // this is static since only 8 or 16 bit signed complex cartesian is supported for now and item packing is always link efficient
      // see 2.2.2 Standard Flow Signal Context Packet in the DIFI spec for complete information
      u_int64_t data_payload_format = bit_depth == 8 ? difi::EIGHT_BIT_SIGNED_CART_LINK_EFF : difi::SIXTEEN_BIT_SIGNED_CART_LINK_EFF;

      u_int32_t state_and_event_id =difi::DEFAULT_STATE_AND_EVENTS; // default no events or state values. See 7.1.5.17 The State and Event Indicator Field of the VITA spec
      // no fractional bw or samp rate supported in gnuradio, see 2.2.2 Standard Flow Signal Context Packet for bandwidth information
      // Bandwidth spec: Refer to section 9.5.1 of the VITA 49.2 (AV49DOT2-2017__Earata.pdf)
      // Nik Ansell: this conversion is incorrect. samp_rate must first be cast to a 64bit int
      u_int64_t to_vita_bw = u_int64_t(samp_rate * .8) << 20; // Converted to fixed point with radix point 20 bits to the left
      u_int64_t to_vita_samp_rate = samp_rate << 20; // Converted to fixed point with radix point 20 bits to the left


      // Nik Ansell: Add time stamps from first context packet
      //u_int32_t full = std::time(nullptr);
      //u_int64_t frac = 0;
      //std::tie(full, frac) = add_frac_full();

      if(context_pack_size == 72)// this check is a temporary work around for a non-compliant hardware device
      {
        pack_u32(&d_context_raw[difi::CONTEXT_PACKET_ALT_OFFSETS[idx++]], 966885376U);
        pack_u64(&d_context_raw[difi::CONTEXT_PACKET_ALT_OFFSETS[idx++]], to_vita_bw);
        pack_u64(&d_context_raw[difi::CONTEXT_PACKET_ALT_OFFSETS[idx++]], 0);
        pack_u64(&d_context_raw[difi::CONTEXT_PACKET_ALT_OFFSETS[idx++]], 0);
        pack_u64(&d_context_raw[difi::CONTEXT_PACKET_ALT_OFFSETS[idx++]], 0);
        pack_u64(&d_context_raw[difi::CONTEXT_PACKET_ALT_OFFSETS[idx++]], to_vita_samp_rate);
        pack_u32(&d_context_raw[difi::CONTEXT_PACKET_ALT_OFFSETS[idx++]], state_and_event_id);
        pack_u64(&d_context_raw[difi::CONTEXT_PACKET_ALT_OFFSETS[idx++]], data_payload_format);

      }
      else
      {
        pack_u32(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0); // Int Timestamp
        pack_u64(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0); // Frac Timestamp
        //pack_u32(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], full); // Int Timestamp?
        //pack_u64(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], frac); // Frac Timestamp?
        // Nik Ansell: I think the next value is the CIF. The first bit in the CIF should be set to 1
        // fo the first context packet. This tells the receiving device that something has changed.
        // The receiving device can then attempt to configure itself using the meta data in the context packet.
        // Many devices will ignore the VITA49 stream is this is not done
        // 10000000000000000000000000000000 in decimal = 2147483648
        //GR_LOG_INFO(this->d_logger, "[" + std::to_string(d_context_packet_count) + "] CIF change bit=1");
        // pack_u32(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0);
        //pack_u32(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 2147483648); 3114369024 / 0xB9A18000
        // The reference point indicates location in the system that the digital samples are conveying
        // information about. The value of 0x64 indicates it is at the RF input for the RF-to-IP
        // direction and the RF output in the IP-to-RF direction.
        GR_LOG_INFO(this->d_logger, "reference_point: " + std::to_string(reference_point));
        GR_LOG_INFO(this->d_logger, "to_vita_bw: " + std::to_string(to_vita_bw));
        GR_LOG_INFO(this->d_logger, "samp_rate: " + std::to_string(to_vita_samp_rate));

        //pack_u32(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0xFBB98000  ); // CIF 11111011101110011000000000000000 0xFBB98000
        

        // pack_u32(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], reference_point);
        // pack_u64(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], to_vita_bw); // 9.5.1 Bandwidth Field
        // pack_u64(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0); // 9.5.5 IF Reference Frequency Field 
        // pack_u64(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0); // 9.5.10 RF Reference Frequency Field
        // pack_u64(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0); // 9.5.4 IF Band Offset Field
        // pack_u32(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0); // 9.5.9 Reference Level Field
        // pack_u32(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0); // 9.5.3 Gain/Attenuation Field
        // pack_u64(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], samp_rate); // 9.5.12 Sample Rate Field
        // pack_u64(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0); // 9.7.3.1 Timestamp Adjustment
        // pack_u32(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], 0); // 9.7.3.3 The Timestamp Calibration Time Field
        // pack_u32(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], state_and_event_id);
        // pack_u64(&d_context_raw[difi::CONTEXT_PACKET_OFFSETS[idx++]], data_payload_format);\

        // bandwidth: 200000 : 00000030d4000000
        // bandwidth: 5000000: 000004c4b4000000

        // samplerate: 265000 : 000004e200000000
        // 

        pack_u32(&d_context_raw[28], 0xB9A18000); // CIF
        //pack_u64(&d_context_raw[32], to_vita_bw); // 9.5.1 Bandwidth Field
        pack_u64(&d_context_raw[32], 0x000004c4b4000000); // 9.5.1 Bandwidth Field
        pack_u64(&d_context_raw[40], 0); // 9.5.5 IF Reference Frequency Field 
        pack_u64(&d_context_raw[48], 0x00084e3786000000); // 9.5.10 RF Reference Frequency Field. If 0 some devices will ignore all data packets
        pack_u32(&d_context_raw[56], 0x00000080); // 9.5.9 Reference Level Field
        pack_u32(&d_context_raw[60], 0x00000380); // 9.5.3 Gain/Attenuation Field
        //pack_u64(&d_context_raw[64], samp_rate); // 9.5.12 Sample Rate Field
        pack_u64(&d_context_raw[64], 0x0000055d4a800000); // 9.5.12 Sample Rate Field
        pack_u32(&d_context_raw[72], 0xa00a0000); // State and event indicators
        pack_u64(&d_context_raw[76], 0xa00001c700000000);  // Data packet format
      }
      d_out_buf.resize(d_data_len);

      d_scaling_mode = scaling;

      if(d_scaling_mode == 1){
        //manual
        d_gain = gain;
        d_offset = offset;
      }
      else if(d_scaling_mode == 2){
          //min-max
          int full_scale = 1 << bit_depth;
          float EPSILON = 0.0001;
          if ((max_iq - min_iq) < EPSILON){
            GR_LOG_ERROR(this->d_logger, "(max_iq - min_iq) too small or is negative, bailing to avoid numerical issues!");
            throw std::runtime_error("(max_iq - min_iq) too small or is negative, bailing to avoid numerical issues!");
          }
          d_gain = float(full_scale) / (max_iq - min_iq);
          d_offset = gr_complex(-1.0 * ((max_iq - min_iq) / 2 + min_iq),-1.0 * ((max_iq - min_iq) / 2 + min_iq));
      }
    }

    template <class T>
    difi_sink_cpp_impl<T>::~difi_sink_cpp_impl()
    {
      if(p_udpsocket)
        delete p_udpsocket;

      if(p_tcpsocket)
        delete p_tcpsocket;
    }

    template <class T>
    int difi_sink_cpp_impl<T>::work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items)
    {

      if(p_tcpsocket)
      {
        if(!p_tcpsocket->is_connected())
        {
          bool res = p_tcpsocket->connect();
          if(!res)
          {
            return 0;
          }
        }
      }

      const T *in = reinterpret_cast<const T*>(input_items[0]);

      if(d_is_paired_mode)
      {
        process_tags(noutput_items);
      }

      for(int i = 0; i < noutput_items; i++)
      {
        gr_complex in_val = gr_complex(in[i].real(), in[i].imag());
        if(d_scaling_mode > 0){
            in_val = (in_val + d_offset) * d_gain;
        }
        this->pack_T(in_val);
        d_current_buff_idx += 2 * d_unpack_idx_size;
        if(d_current_buff_idx >= d_out_buf.size())
        {
          // Nik Ansell: Only send context packets when not in paired mode? : if(!d_is_paired_mode
          // This does not seem to comply with the VITA49 standard of always sending context packets
          // Update to always send them as a test...
          // Plus update to send a batch of them at the start of the transmission
          // to give the receiving device more of a chance.
          // if(!d_is_paired_mode and d_packet_count % d_contex_packet_interval == 0)
          if(d_packet_count % d_contex_packet_interval == 0)
          {
            if (d_packet_count < 1)
            {
              GR_LOG_INFO(this->d_logger, "[" + std::to_string(d_context_packet_count) + "] Sending initial batch of context packets");
              for (int i = 0; i < 10; i++) {
                send_context();
              }
            }
            else
            {
              send_context(); 
            }
          }

          auto to_send = pack_data();
          if(p_udpsocket)
          {
            p_udpsocket->send(&to_send[0],to_send.size());
          }
          if(p_tcpsocket)
          {
            p_tcpsocket->send(&to_send[0],to_send.size());
          }

          d_pkt_n = (d_pkt_n + 1) % difi::VITA_PKT_MOD;
          d_current_buff_idx = 0;
          d_pcks_since_last_reference++;
          d_packet_count++;
        }
      }
      return noutput_items;
    }

    template <class T>
    void difi_sink_cpp_impl<T>::process_tags(int noutput_items)
    {
      auto abs_offset = this->nitems_read(0);
      std::vector<tag_t> tags;
      this->get_tags_in_range(tags, 0, abs_offset, abs_offset + noutput_items);
      for(tag_t tag : tags)
      {
        if(pmt::eqv(d_context_key, tag.key))
        {
          auto raw = pmt::dict_ref(tag.value, pmt::intern("raw"), pmt::get_PMT_NIL());;
          std::vector<int8_t> to_send = pmt::s8vector_elements(raw);
          d_raw = to_send;
          if(p_udpsocket)
          {
            p_udpsocket->send(&to_send[0], to_send.size());
          }

          if(p_tcpsocket)
          {
            p_tcpsocket->send(&to_send[0], to_send.size());
          }

          std::copy(to_send.begin(), to_send.begin() + difi::DIFI_HEADER_SIZE, d_raw.begin());
          // Get timestamps and stream id from incoming VITA49 context packet
          d_full = u_int32_t(pmt::to_long(pmt::dict_ref(tag.value, pmt::mp("full"), pmt::get_PMT_NIL())));
          d_frac = pmt::to_uint64(pmt::dict_ref(tag.value, pmt::mp("frac"), pmt::get_PMT_NIL()));
          d_stream_number = pmt::to_uint64(pmt::dict_ref(tag.value, pmt::mp("stream_num"), pmt::get_PMT_NIL()));
          d_pcks_since_last_reference = 0;
        }
        else if(pmt::eqv(d_pkt_n_key, tag.key))
        {
          d_pkt_n = (d_pkt_n + 1) % difi::VITA_PKT_MOD; // missed packet, so account for this
          // Get timestamps and signal data packet length from incoming VITA49 signal data packet
          d_full = u_int32_t(pmt::to_long(pmt::dict_ref(tag.value, pmt::mp("full"), pmt::get_PMT_NIL())));
          d_frac = pmt::to_uint64(pmt::dict_ref(tag.value, pmt::mp("frac"), pmt::get_PMT_NIL()));
          d_data_len = pmt::to_uint64(pmt::dict_ref(tag.value, pmt::mp("data_len"), pmt::get_PMT_NIL())) - difi::DIFI_HEADER_SIZE;
          if (d_data_len % (2 * d_unpack_idx_size) != 0)
          {
            GR_LOG_WARN(this->d_logger, "data len cannot fit an integer number of samples, something is misconfigured");
          }
          d_samples_per_packet = d_data_len / (2 * d_unpack_idx_size);
          d_out_buf.clear(); // clear the data since we missed samples, start fresh
          d_out_buf.resize(d_data_len);
          d_current_buff_idx = 0;
          d_time_adj = (double)d_samples_per_packet / d_full_samp;
          d_pcks_since_last_reference = 0;
        }
        else if(pmt::eqv(d_static_change_key, tag.key))
        {
          d_static_bits = pmt::to_uint64(tag.value);
        }
      }
    }

    // Create VITA49 Signal data packet
    template <class T>
    std::vector<int8_t> difi_sink_cpp_impl<T>::pack_data()
    {
      std::vector<int8_t> to_send(difi::DIFI_HEADER_SIZE + d_out_buf.size());
      u_int32_t full;
      u_int64_t frac;
      std::tie(full, frac) = add_frac_full();
      u_int32_t header = d_static_bits ^ d_pkt_n << 16 ^ (d_data_len + difi::DIFI_HEADER_SIZE) / 4;
      pack_u32(&to_send[0], header);
      std::copy(d_raw.begin() + 8, d_raw.begin() + 16, to_send.begin() + 8);
      pack_u32(&to_send[16], full);
      pack_u64(&to_send[20], frac);
      std::copy(d_out_buf.begin(), d_out_buf.end(), to_send.begin() + difi::DIFI_HEADER_SIZE);
      return to_send;
    }

    // Send a Context Packet
    template <class T>
    void difi_sink_cpp_impl<T>::send_context()
    {
        // Nik Ansell: Why not update the timestamps for all context packets?
        if(d_context_packet_size == 108 || d_context_packet_size == 84)// this check is a temporary work around for a non-compliant hardware device
        {
            u_int32_t full;
            u_int64_t frac;
            std::tie(full, frac) = add_frac_full();
            pack_u32(&d_context_raw[16], full);
            pack_u64(&d_context_raw[20], frac);
        }
        u_int32_t header = d_context_static_bits ^ d_context_packet_count << 16 ^ (d_context_packet_size / 4);
        pack_u32(&d_context_raw[0], header);

        // Nik Ansell: Update the Change indicator (first bit) in the CIF as required 
        if (d_context_packet_count < 1) {
          pack_u32(&d_context_raw[28], 0xB9A18000  );  
        }
        else{
          pack_u32(&d_context_raw[28], 0x39A18000  );   
        }
        
        
        if(p_udpsocket)
        {
          p_udpsocket->send((int8_t*)&d_context_raw[0],d_context_raw.size());
        }

        if(p_tcpsocket)
        {
          p_tcpsocket->send((int8_t*)&d_context_raw[0], d_context_raw.size());
        }
        // Calculate the next VITA49 sequence number
        d_context_packet_count = (d_context_packet_count + 1) % difi::VITA_PKT_MOD;
    }

    template <class T>
    std::tuple<u_int32_t, u_int64_t> difi_sink_cpp_impl<T>::add_frac_full()
    {
      auto frac = d_frac;
      auto full = d_full;
      auto time_adj = d_time_adj * d_pcks_since_last_reference;
      frac += u_int64_t((time_adj - u_int64_t(time_adj)) * difi::PICO_CONVERSION);
      if(frac >= difi::PICO_CONVERSION)
      {
          frac = d_frac % difi::PICO_CONVERSION;
          full += 1;
      }
      full += u_int32_t(time_adj);
      return std::make_tuple(full, frac);
    }
    template <class T>
    void difi_sink_cpp_impl<T>::pack_T(T val)
    {
      auto re = (static_cast<int16_t>(val.real()));
      auto im = (static_cast<int16_t>(val.imag()));
      memcpy(&d_out_buf[d_current_buff_idx], &re, d_unpack_idx_size);
      memcpy(&d_out_buf[d_current_buff_idx + d_unpack_idx_size], &im, d_unpack_idx_size);
    }

    template class difi_sink_cpp<gr_complex>;
    template class difi_sink_cpp<std::complex<char>>;

  } /* namespace difi */
} /* namespace gr */

