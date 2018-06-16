defmodule Networking do
  # ----- Messing around with ARP spoofing... it works... though it's hacky.
  # ping the tap device with
  # arping -I tap0 "192.168.123.4"
  # check the arp table with
  # arp
  def start_tap_and_reply_to_arpings do
    {:ok, socketish} = :tuncer.create("", [:tap, :no_pi, active: false])
    :tuncer.up(socketish, '192.168.123.4')
    fd = :tuncer.getfd(socketish)
    reply_to_arpings(fd)
  end

  def reply_to_arpings(fd) do
    with {:ok, buf} <- :tuncer.read(fd, 1500) do
      eth = parse_eth_header(buf)
      if is_arp_packet(eth) do
        arp = parse_arp_packet(eth)
        body = parse_arp_request_body(arp)
        reply_to_arp_request(arp, body, buf, fd)
      end
    end
    reply_to_arpings(fd)
  end

  def reply_to_arp_request(header, body, buf, fd) do
    # TAKEN FROM ONLINE DOCS
    # Swap hardware and protocol fields, putting the local
    # hardware and protocol addresses in the sender fields.
    # Set the ar$op field to ares_op$REPLY
    # Send the packet to the (new) target hardware address on
    # the same hardware on which the request was received.
    IO.inspect body
    IO.inspect header
    # Because I don't know how to mutate binaries in Elixir.
    # 20 bytes of eth and arp header and then 2 bytes of opcode and then the body
    <<before_opcode :: binary-size(20), 0, 1, arp_body :: binary-size(20)>> = buf
    hardware_addr = <<255, 255, 255, 255, 255, 255>>
    addr = <<192, 168, 123, 4>>
    new_body = hardware_addr <> addr <> body.smac <> body.sip
    buf2 = before_opcode <> <<0, 2>> <> new_body
    :ok = :tuncer.write(fd, buf2)
  end

  def parse_arp_request_body(%{opcode: 1, hwtype: 1, protype: 2048, hwsize: 6, prosize: 4, body: body}) do
    <<smac :: binary-size(6),
      sip  :: binary-size(4),
      dmac :: binary-size(6),
      dip  :: binary-size(4)>> = body
    %{
      smac: smac,
      sip: sip,
      dmac: dmac,
      dip: dip
    }
  end

  def parse_eth_header(<<eth :: binary-size(14), body :: binary>>) do
    <<dmac      :: binary-size(6),
      smac      :: binary-size(6),
      ethertype :: unsigned-big-integer-size(16)>> = eth
    %{
      dmac: dmac,
      smac: smac,
      ethertype: ethertype,
      body: body
     }
  end

  def is_arp_packet(%{ethertype: ethertype}) do
    Integer.to_string(ethertype, 16) == "806" # 0x0806 is arp
  end

  def parse_arp_packet(%{body: body}) do
    <<hwtype  :: unsigned-big-integer-size(16),
      protype :: unsigned-big-integer-size(16),
      hwsize,
      prosize,
      opcode  :: unsigned-big-integer-size(16),
      body    :: binary>> = body
    %{
      hwtype: hwtype,
      protype: protype,
      hwsize: hwsize,
      prosize: prosize,
      opcode: opcode,
      body: body
    }
  end
end
