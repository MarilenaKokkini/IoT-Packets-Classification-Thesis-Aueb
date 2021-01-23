import binascii
import csv
from itertools import product
import pyshark
import os
from datetime import date, datetime
import sys

previous_packet_size = 0
previous_packet_time = 0


# THE PORT ARE VALID DUE TO https://www.iana.org/assignments/service-names-port-numbers/service-names
# -port-numbers.xhtml?search=amqp
def create_hex_from_bits(bits):  # pass the parameter like that: '00100001'
    """converts bits into hex in order to find them in the packet"""
    result = "x%x" % (int(bits, 2))
    return result


# REFERENCE: https://docs.solace.com/MQTT-311-Prtl-Conformance-Spec/MQTT%20Control%20Packet%20format.htm
def create_mqtt_first_byte():
    """this function generates the first mqtt byte through flags"""
    # control field(packet type-->4 bits, flags-->4 bits)
    # if dup = 0 then qos = 0
    # calculate remaining length
    packet_type = {
        # "Reserved": '0000',  # we use only 4 bits, so the rest 4
        # are the length of the packet... cannot be null
        "CONNECT": '00010000',
        "CONNACK": '00100000',
        "PUBLISH_DUP0_Q0_R0": '00110000',
        "PUBLISH_DUP0_Q3_R1": '00110111',
        "PUBLISH_DUP0_Q3_R0": '00110110',
        "PUBLISH_DUP0_Q2_R1": '00110101',
        "PUBLISH_DUP0_Q2_R0": '00110100',
        "PUBLISH_DUP0_Q1_R1": '00110011',
        "PUBLISH_DUP0_Q1_R0": '00110010',
        "PUBLISH_DUP0_Q0_R1": '00110001',
        # "PUBLISH_DUP1_Q0_R0": '00111000',
        "PUBLISH_DUP1_Q1_R0": '00111010',
        "PUBLISH_DUP1_Q2_R0": '00111100',
        "PUBLISH_DUP1_Q3_R0": '00111110',
        # "PUBLISH_DUP1_Q0_R1": '00111001',
        "PUBLISH_DUP1_Q1_R1": '00111011',
        "PUBLISH_DUP1_Q2_R1": '00111101',
        "PUBLISH_DUP1_Q3_R1": '00111111',
        "PUBACK": '01000000',
        "PUBREC": '01010000',
        "PUBREL": '01100010',
        "PUBCOMP": '01110000',
        "SUBSCRIBE": '10000010',
        "SUBACK": '10010000',
        "UNSUBSCRIBE": '10100010',
        "UNSUBACK": '10110000',
        "PINGREQ": '11000000',
        "PINGRESP": '11010000',
        "DISCONNECT": '11100000'
    }
    bits_to_hex = [create_hex_from_bits(value) for value in packet_type.values()]
    return bits_to_hex


# REFERENCES: https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
def is_amqp(payload, current_packet, type_protocol):  # type_protocol = TCP/UDP
    """Decides whether the packet is amqp or not"""
    answer = "no"
    if 'AMQP' in str(current_packet.layers):
        answer = "yes"
        return answer
    if "AMQP" in payload:  # initiates the connection (first amqp packet)
        answer = "yes"
        return answer
    else:
        if len(payload) >= 8:  # Header, having a fixed size (8 byte);
            # frame end is always %xce
            end_code = "\\xce"
            index = payload.find(end_code)
            right_index = len(payload) - 5
            if index == right_index:
                answer = "yes"
                return answer
    # also packets from given ports
    src_port = current_packet[type_protocol].srcport
    dst_port = current_packet[type_protocol].dstport
    if (src_port == 5671) or (dst_port == 5671) or (src_port == 5672) or (dst_port == 5672):
        answer = "yes"
        return answer

    return answer


def create_coap_first_byte():
    # version is always 01 = coap version 1
    ver = '01'
    my_types = {"confirmable": '00', "Non-cofirmable": '01', "Acknowledgement": '10', "Reset": '11'}
    token_length = {0: '0000', 1: '0001', 2: '0010', 3: '0011', 4: '0100', 5: '0101', 6: '0110', 7: '0111',
                    8: '1000'}
    first_byte = []
    for protocol_type, token in product(my_types.values(), token_length.values()):  # removed nested loop
        combination = ver + protocol_type + token
        hex_combination = create_hex_from_bits(combination)
        if hex_combination not in first_byte:
            # create possible combinations
            first_byte.append(hex_combination)
    return first_byte


def is_coap(payload, current_packet, type_protocol, first_byte):
    # first byte is the list with the possible combinations for a coap byte
    answer = "no"
    if 'COAP' in str(current_packet.layers):
        answer = "yes"
        return answer
    if len(payload) >= 4:  # fixed header 4 bytes
        for byte in first_byte:
            if byte in payload[:7]:
                answer = "yes"
                return answer

        src_port = current_packet[type_protocol].srcport
        dst_port = current_packet[type_protocol].dstport
        if (src_port == 5683) or (dst_port == 5683):
            answer = "yes"
            return answer

    return answer


def is_mqtt(payload, list_with_codes, current_packet, type_protocol):
    """decide if the packet uses mqtt or not"""
    answer = "no"
    if 'MQTT' in str(current_packet.layers):
        answer = "yes"
        return answer
    if "MQTT" in payload:
        answer = "yes"
        return answer

    for mqtt_code in list_with_codes:  # e.g xe0
        exact_code = "\\" + mqtt_code + "\\"  # e.g \xe0\
        if exact_code in payload[:7]:
            answer = "yes"
            return answer

    # also packets from given ports
    src_port = current_packet[type_protocol].srcport
    dst_port = current_packet[type_protocol].dstport
    if (src_port == 1883) or (dst_port == 1883) or (src_port == 8883) or (dst_port == 8883):
        answer = "yes"
        return answer

    return answer


def if_file_exists_delete_it():
    """because write_all method appends on file, we need to delete it if was previously existed
    in order to avoid a wrong output"""
    if os.path.exists("all.csv"):
        print("file deleted")
        os.remove("all.csv")


def is_malicious_dataset():
    """check if the packets come from honeypot or not"""
    value = input("Are the packets from the honeypot? (yes/no answer)")
    if value.lower() == "yes":
        print("malicious dataset")
        return True
    else:
        print("the dataset is not malicious")
        return False


def write_headers():
    """will write only the headers"""
    if os.path.exists("all.csv"):
        print("output already exists")
    else:
        fileName = 'all.csv'
        with open(fileName, 'w', newline='') as csv_file:
            csv_file = csv.writer(csv_file, delimiter=',')
            csv_file.writerow(
                ['app_protocol', 'transport_protocol', 'layer', 'mac_src', 'mac_dst', 'src_ip', 'dst_ip',
                 'src_port', 'dst_port', 'pkt_size', 'is_encrypted', 'payload size', 'payload_ratio', 'previous_ratio',
                 'packet_time_diff', 'payload', 'p_date', 'p_time', 'flag'])


def write_all(app_protocol, type_protocol, layer, mac_src, mac_dst, src_ip, dst_ip,
              src_port, dst_port, pkt_size, is_encrypted, payload_size, payload_ratio, previous_ratio,
              packet_time_diff, payload, p_date, p_hour,flag):
    """creates a file with all packets"""
    fileName = 'all.csv'
    # append mode
    with open(fileName, 'a', newline='') as csv_file:  # automatically close the file
        csv_file = csv.writer(csv_file, delimiter=',')

        csv_file.writerow([app_protocol, type_protocol, layer, mac_src, mac_dst, src_ip, dst_ip,
                           src_port, dst_port, pkt_size, is_encrypted, payload_size, payload_ratio, previous_ratio,
                           packet_time_diff, payload, p_date, p_hour, flag])

    # References: https://stackoverflow.com/questions/4959741/python-print-mac-address-out-of-6-byte-string


def prettify(mac_string):
    """convert byte format to hex format, about mac"""
    return ':'.join('%02x' % ord(b) for b in mac_string)


def extract_characteristics_from_packet(pkt, previous_packet_time, previous_packet_size, payload):
    """ this method extracts the most important characteristics of the packets, probably will be used in Ml"""
    # 1st vital characteristic is packet length
    pkt_size = len(pkt)
    # 2nd vital characteristic is whether the packet is encrypted
    is_encrypted = 0
    layer_level = 0
    searching_layers = True  # e.g. Ethernet, Ip, Icmp, Raw
    while searching_layers:
        layer = pkt.layers
        if layer is not None:
            if 'SSL' in layer:  # encryption protocols
                is_encrypted = 1  # encrypted packet
            else:
                searching_layers = False
            layer_level += 1  # check next layer
    # 3rd vital characteristic is the payload size
    # 4rth vital characteristic is the payload ratio
    payload_size = len(payload)
    payload_ratio = (payload_size / pkt_size) * 100
    # 5th vital characteristic is previous packet ratio
    # defaults to 0 for the first packet of the session
    if previous_packet_size != 0:
        previous_ratio = (pkt_size / previous_packet_size) * 100
    else:
        previous_ratio = 1
        previous_packet_size = pkt_size
    # 6th vital characteristic is time difference
    if previous_packet_time != 0:
        packet_time_diff = pkt.sniff_time - previous_packet_time
    else:
        packet_time_diff = 0
        previous_packet_time = pkt.sniff_time

    # 7th vital characteristic is payload content
    # convert to hex type
    payload_fix_format_type = binascii.hexlify(bytes(payload))

    return pkt_size, is_encrypted, payload_size, payload_ratio, previous_packet_time, \
           previous_packet_size, previous_ratio, packet_time_diff, payload_fix_format_type


def find_first_layer_protocol(pkt):
    """get mac address src and dst and first layer"""
    try:
        mac_src_in_bytes = str(pkt.eth.src)
        mac_src = prettify(mac_src_in_bytes)
        mac_dst_in_bytes = str(pkt.eth.dst)
        mac_dst = prettify(mac_dst_in_bytes)
        layer = "Ethernet"
    except AttributeError:
        mac_src = ""
        mac_dst = ""
        layer = "CookedLinux"

    return mac_src, mac_dst, layer


def get_date_and_time(pkt):
    """get the date and the time of the packet"""
    pkt_time = int(float(pkt.sniff_timestamp))
    p_date = datetime.fromtimestamp(pkt_time).strftime('%Y-%m-%d ')  # format: 2020-10-08
    p_hour = datetime.fromtimestamp(pkt_time).strftime('%H:%M:%S')  # format: 22:40:41
    return p_date, p_hour


def get_ip_addresses(pkt):
    """get src and dst mac"""
    # get ip addresses
    src_ip = pkt["IP"].src
    dst_ip = pkt["IP"].dst
    return src_ip, dst_ip


def get_ports(pkt, type_protocol):
    """get ports: dst and src"""
    src_port = pkt[type_protocol].srcport
    dst_port = pkt[type_protocol].dstport
    print("Port: " + src_port)
    return src_port, dst_port


def store_data(app_protocol, pkt, type_protocol, layer, mac_src, mac_dst, src_ip, dst_ip, src_port, dst_port, p_date,
               p_hour, payload, flag):
    global previous_packet_size
    global previous_packet_time

    pkt_size, is_encrypted, payload_size, payload_ratio, previous_packet_time, \
    previous_packet_size, previous_ratio, packet_time_diff, payload = extract_characteristics_from_packet(
        pkt, previous_packet_time, previous_packet_size, payload)

    write_all(app_protocol, type_protocol, layer, mac_src, mac_dst, src_ip, dst_ip,
              src_port, dst_port, pkt_size, is_encrypted, payload_size, payload_ratio, previous_ratio,
              packet_time_diff, payload, p_date, p_hour, flag)


def pcap_pkt_reader():
    """extracts the basic information of the packets, only for the 3 basic IoT protocols"""
    file_name = 'save.pcap'
    # if this file is not in the system...
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)
    # if the file is in the system...
    else:
        print('file found!')
        # packets_list = rdpcap(file_name)

        tcp_counter = 0
        udp_counter = 0
        mqtt_counter = 0
        coap_counter = 0
        amqp_counter = 0

        # initialise list with mqtt codes
        list_with_mqtt_codes = create_mqtt_first_byte()
        list_with_coap_codes = create_coap_first_byte()

        # counter = 0
        pkt_id = 0
        # if_file_exists_delete_it()  # delete the previous output file
        write_headers()  # initialise the file
        flag = is_malicious_dataset()
    try:
        packets = pyshark.FileCapture(file_name)
        print("read packets")
        for pkt in packets:
            pkt_id += 1
            print(pkt_id)
            # date and time of the packet
            p_date, p_hour = get_date_and_time(pkt)

            if ('HTTP') not in str(pkt.layers):
                # TCP CASE
                if "TCP" in pkt.transport_layer:
                    try:
                        type_protocol = "TCP"
                        payload = pkt.tcp.payload
                        payload = bytes.fromhex(payload.replace(":", ""))
                    except AttributeError:
                        payload = ""
                        continue
                if "UDP" in pkt.transport_layer:
                    try:
                        type_protocol = "UDP"
                        print(type_protocol)
                        if 'COAP' in str(pkt.layers):
                            print("COAP")
                        payload = pkt.data.data
                        payload = bytes.fromhex(payload.replace(":", ""))
                    except AttributeError:
                        payload = ""
                        continue

                # get mac addresses and first layer
                mac_src, mac_dst, layer = find_first_layer_protocol(pkt)

                # get ip addresses
                src_ip, dst_ip = get_ip_addresses(pkt)

                # get port numbers
                src_port, dst_port = get_ports(pkt, type_protocol)

                # check for IoΤ protocols
                # search tcp payload in order to find the application layer level

                str_payload = str(payload)
                # print("Payload: "+str_payload)
                if str_payload:  # not b'' TCP payload is zero so there is no header fro the application layer

                    # capture AMQP protocol:
                    amqp_answer = is_amqp(str_payload, pkt, type_protocol)
                    if amqp_answer == "yes":
                        amqp_counter += 1
                        app_protocol = "AMQP"
                        # store the information about amqp protocol
                        store_data(app_protocol, pkt, type_protocol, layer, mac_src, mac_dst, src_ip, dst_ip, src_port,
                                   dst_port, p_date, p_hour, payload,flag)
                    else:
                        # capture mqtt protocol
                        mqtt_answer = is_mqtt(str_payload, list_with_mqtt_codes, pkt, type_protocol)
                        if mqtt_answer == "yes":
                            mqtt_counter += 1
                            app_protocol = "MQTT"
                            # store the information about mqtt protocol
                            store_data(app_protocol, pkt, type_protocol, layer, mac_src, mac_dst, src_ip, dst_ip,
                                       src_port, dst_port, p_date, p_hour, payload,flag)
                        else:
                            # capture Coap protocol:
                            coap_answer = is_coap(str_payload, pkt, type_protocol, list_with_coap_codes)
                            if coap_answer == "yes":
                                coap_counter += 1
                                app_protocol = "COAP"
                                store_data(app_protocol, pkt, type_protocol, layer, mac_src, mac_dst, src_ip, dst_ip,
                                           src_port, dst_port, p_date, p_hour, payload, flag)
    finally:
        packets.close()

    print("end")
    # print(f"we have {udp_counter} udp packets.")
    # print(f"we have {mqtt_counter} MQTT packets.")
    # print(f"we have {coap_counter} CoAp packets.")
    # print(f"we have {amqp_counter} AMQP packets.")


pcap_pkt_reader()
