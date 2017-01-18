require 'bit-struct'
require 'socket'
require_relative './timer'

module IEEE80211
  MTU = 2312
  
  module Radiotap
    class Header < BitStruct
      default_options endian: :little
      
      unsigned :version,  8
      padding  :pad,      8
      unsigned :len,     16
      unsigned :present, 32
      rest     :flags
    end
    
    class Channel < BitStruct
      default_options endian: :little
      
      BIT_NUM = 3
      
      CCK  = 0x0020
      OFDM = 0x0040
      GHZ2 = 0x0080
      GHZ5 = 0x0100
      
      unsigned :frequency, 16
      unsigned :flags,     16
    end
    
    class Rate < BitStruct
      BIT_NUM = 2
      
      unsigned :rate, 8
    end
    
    class Flags < BitStruct
      BIT_NUM = 1
      
      unsigned :flags, 8
    end
    
    class Timestamp < BitStruct
      BIT_NUM = 0
      
      unsigned :timestamp, 64, endian: :little
    end
  end
  
  class Header1Addr < BitStruct
    default_options endian: :little
    
    unsigned   :frame_control, 16, format: '0x%04X'
    unsigned   :duration_id,   16, format: '0x%04X'
    hex_octets :addr1,         48
  end
  
  class Header3Addr < BitStruct
    default_options endian: :little
    
    unsigned   :frame_control, 16, format: '0x%04X'
    unsigned   :duration_id,   16, format: '0x%04X'
    hex_octets :addr1,         48
    hex_octets :addr2,         48
    hex_octets :addr3,         48
    unsigned   :seq_ctrl,      16, format: '0x%04X'
  end
  
  class Header4Addr < BitStruct
    default_options endian: :little
    
    unsigned   :frame_control, 16, format: '0x%04X'
    unsigned   :duration_id,   16, format: '0x%04X'
    hex_octets :addr1,         48
    hex_octets :addr2,         48
    hex_octets :addr3,         48
    unsigned   :seq_ctrl,      16, format: '0x%04X'
    hex_octets :addr4,         48
  end
  
  class HeaderQoS < BitStruct
    default_options endian: :little
    
    unsigned   :frame_control, 16, format: '0x%04X'
    unsigned   :duration_id,   16, format: '0x%04X'
    hex_octets :addr1,         48
    hex_octets :addr2,         48
    hex_octets :addr3,         48
    unsigned   :seq_ctrl,      16, format: '0x%04X'
    unsigned   :qos_ctrl,      16, format: '0x%04X'
  end

  class BeaconHeader < BitStruct
    default_options endian: :little
    
    unsigned :timestamp,       64
    unsigned :beacon_interval, 16
    unsigned :capabilities,    16
  end

  class AssociationResponseHeader < BitStruct
    default_options endian: :little
    
    unsigned :capabilities,   16
    unsigned :status_code,    16
    unsigned :association_id, 16
  end
  
  class TagHeader < BitStruct
    unsigned :number, 8
    unsigned :len,    8
    rest     :data
  end
end

class XboneController
end

class Xbone
  def initialize(interface, frequency: 5240)
    @seq_counter = 0

    @socket = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW)
    #@socket = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, Socket::IPPROTO_RAW)
    
    # bind socket to interface
    ifreq = [interface].pack 'a32'
    @socket.ioctl(0x8933, ifreq)
    #@socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_BINDTODEVICE, ifreq)
    #@socket.bind([Socket::AF_PACKET, Socket::IPPROTO_RAW].pack('sn') + ifreq[16, 4]+ ("\x00" * 12))
    @socket.bind([Socket::AF_PACKET, 3].pack('sn') + ifreq[16, 4]+ ("\x00" * 12))
    #@socket.setsockopt(0x0107, 0x0001, [0x0001].pack('s') + ("\x00" * 14))
    
    # get MAC address of interface
    ifreq = [interface].pack 'a32'
    @socket.ioctl(0x8927, ifreq)
    @src_mac = ifreq[18, 6].bytes.map { |c| c.to_s 16 }.join ':'
    puts @src_mac

    #@src_mac = '62:45:b4:f4:41:51'.split(':').map { |c| c.to_i 16 }.pack 'C*'
    @src_mac = '62:45:b4:f4:41:51'
    
    # prepare RadioTap header fields
    @rt_channel           = IEEE80211::Radiotap::Channel.new
    @rt_channel.frequency = frequency
    @rt_channel.flags     = IEEE80211::Radiotap::Channel::GHZ5 | IEEE80211::Radiotap::Channel::OFDM
    @rt_rate              = IEEE80211::Radiotap::Rate.new
    @rt_rate.rate         = 6000 / 500 # 6 Mbit/s
    @rt_flags             = IEEE80211::Radiotap::Flags.new
    @rt_flags.flags       = 0
  end

  # starts sending beacons and listens for controller data
  def run
    Thread.start do
      Timer.every 0.10235 do
        header = IEEE80211::Header3Addr.new
        header.frame_control = 0x0080 # Beacon frame
        header.duration_id   = 0
        header.addr1         = 'ff:ff:ff:ff:ff:ff'
        header.addr2         = @src_mac
        header.addr3         = @src_mac
        header.seq_ctrl      = @seq_counter << 4

        send_frame(header + beacon_frame)
      end
    end
    loop do
      packet, addr_info = @socket.recvfrom(IEEE80211::MTU)

      # remove Radiotap header
      rt = IEEE80211::Radiotap::Header.new(packet)
      packet = packet[rt.len .. - 1]

      next if packet.nil? or packet.length < 24

      header = IEEE80211::Header3Addr.new(packet)
      packet = packet[header.length .. -1]

      # ignore packets that are not destined for us
      next unless header.addr1 == @src_mac or header.frame_control & 0xff == 0x40 # don't ignore probe requests to broadcast
      src_mac = header.addr2

      #puts header.inspect_detailed

      puts 'packet received'

      # ACK every packet that IS destined for us
      send_ack src_mac unless [0xd4].include?(header.frame_control & 0xff) # don't ACK ACKs

      frame_control, duration_id, body = case header.frame_control & 0xff
                                           when 0x00
                                             puts '  assoc req'
                                             handle_association_request packet
                                           when 0x40
                                             puts '  probe req'
                                             handle_probe_request packet
                                           when 0x20
                                             puts '  reassoc req'
                                             handle_association_request packet
                                           when 0xa0
                                             puts '  controller disconnected'
                                           when 0xc8
                                             puts '  QoS null (ping)'
                                             handle_ping packet
                                           when 0x88
                                             puts 'actual data! whohoo!'
                                           else
                                             puts '  unknown frame'
                                             puts header.inspect_detailed
                                         end

      next if body.nil?

      header = IEEE80211::Header3Addr.new
      header.frame_control = frame_control
      header.duration_id   = duration_id
      header.addr1         = src_mac
      header.addr2         = @src_mac
      header.addr3         = @src_mac
      header.seq_ctrl      = @seq_counter << 4

      send_frame(header + body)
    end
  end
  
  # sends the given frame, prepended with the radiotap header
  def send_frame(frame)
    @socket.send(radiotap_header + frame, 0)
    @seq_counter += 1
  end
  
  private
  
  # every single packet that is directed to us is being ACK'ed
  def send_ack(mac)
    puts '  acking frame'
    header               = IEEE80211::Header1Addr.new
    header.frame_control = 0x00d4
    header.duration_id   = 0x0064
    header.addr1         = mac
    send_frame(header)
  end

  # prepares the radiotap header which is prepanded to the actual packet
  # and evaluated by the Linux kernel
  def radiotap_header
    timestamp           = IEEE80211::Radiotap::Timestamp.new
    timestamp.timestamp = (Time.now.to_f*1e6).floor

    fields = [@rt_channel, @rt_rate, @rt_flags, timestamp]

    # create Radiotap header
    rt = IEEE80211::Radiotap::Header.new
    rt.present = fields.map     { |flag| 1 << flag.class::BIT_NUM }.inject(:|)
    rt.flags   = fields.sort_by { |flag| flag.class::BIT_NUM }.inject(:+)
    rt.len     = rt.length

    rt
  end
  
  # "hey its me ur xbone dongle"
  def beacon_frame
    beacon = IEEE80211::BeaconHeader.new
    beacon.timestamp       = (Time.now.to_f*1e6).floor
    beacon.beacon_interval = 0x0064 # 1024 milliseconds
    beacon.capabilities    = 0xc631 # Transmitter is an AP
                                    # CFP is not used for unicast data frames
                                    # AP can support WEP (although it's not used)
                                    # Short preamble is allowed
                                    # Short slot time is used
                                    # Delayed Block Ack is implemented
                                    # Immediate Block Ack is implemented
    
    tag1 = IEEE80211::TagHeader.new # empty SSID
    tag2 = IEEE80211::TagHeader.new # MS vendor specific tag
    tag2.number = 0xdd
    tag2.data   = [ 0x00, 0x50, 0xf2, 0x11, 0x01, 0x10, 0x00, 0xa1,
                    0x28, 0x9d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ].pack 'C*'
    tag2.len = tag2.data.length
    
    beacon + tag1 + tag2
  end

  def handle_probe_request(packet)
    return 0x0050, 0x002c, beacon_frame
  end
  
  def handle_association_request(packet)
    ar = IEEE80211::AssociationResponseHeader.new
    ar.capabilities   = 0x0000
    ar.status_code    = 0x0110
    ar.association_id = 0x0f00 # maybe +1 for every controller?
    
    tag = IEEE80211::TagHeader.new # empty tag
    
    return 0x0010, 0x002c, ar + tag*4
  end

  def handle_ping(packet)
    puts 'pong'
    return 0x02c8, 0x0064, "\x00"*4
  end
end

xbone = Xbone.new(ARGV[0])
xbone.run
