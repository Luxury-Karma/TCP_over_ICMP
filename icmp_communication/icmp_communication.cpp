/*
TCP Over ICMP by Alexandre Gauvin

*/

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WS2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <IcmpAPI.h>
#include <string>
#include <cstring>
#include <thread>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

using namespace std;




struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};


class icmp_tcp {
private: 
    static constexpr WORD FLAG_SIZE = 1; // Flag size in byte
    static constexpr WORD SEQ_ACK_NUM_SIZE = 8;  // sequance and ackk in byte ( real size is x2 ) 
    static constexpr WORD CHECK_SUM_SIZE = 3; // Check sum size in byte 
    static constexpr WORD ACTUAL_PAYLOAD_SIZE = 100; // Data size we are sending 
    static constexpr WORD SPLIT_SIZE = 5;

    static constexpr WORD MAXIMUM_PAYLOAD_SIZE = FLAG_SIZE + (SEQ_ACK_NUM_SIZE * 2) + CHECK_SUM_SIZE + ACTUAL_PAYLOAD_SIZE + (SPLIT_SIZE * 4); // total size of the payload including separator

    static constexpr char PADDING = ' '; // if the string finish with white space that is padding

    // TCP flags (lets do hand shake and all ! 
    static constexpr char SYN = 's';
    static constexpr char ACK = 'a';
    static constexpr char SYN_ACK = 'z';
    static constexpr char FIN = 'f';
    static constexpr char FIN_ACK = 'q';
    static constexpr char PAYLOAD_FLAG = 'p';
    const std::string SPLIT = "-^|^-";// Use to split the section of the payload

    /* TODO: make this more good */
    map<string, string> active_connection_information;
    /* THIS HERE !!! */

    // checksum for ICMP packet
    uint16_t checksum(uint16_t* buffer, int size) {
        uint32_t cksum = 0;
        while (size > 1) {
            cksum += *buffer++;
            size -= 2;
        }
        if (size) cksum += *(uint8_t*)buffer;
        cksum = (cksum >> 16) + (cksum & 0xFFFF);
        cksum += (cksum >> 16);
        return (uint16_t)(~cksum);
    }

    // === Region payload manipulation =====

    int calculate_split(char original_payload[]) {
        int size = strlen(original_payload); // for now we ignore the null terminator 

        long split = ceil(static_cast<float>(size) / MAXIMUM_PAYLOAD_SIZE); // give us the amount of split we will need 
    cout << "String size is : " << size << endl;
    cout << "Amount of split needed : " << split << endl;

        return split; // error handle latter
    }

    // Maybe need to reformat to be sur it work but this version 1 should be enough
    char* resized_char(char original_payload[], int split_placement) {
        int position_placement = split_placement * ACTUAL_PAYLOAD_SIZE;
        std::string partial_payload;
        int length = strlen(original_payload);

        for (short i = 0; i < ACTUAL_PAYLOAD_SIZE; i++) {
            int position = i + position_placement;
            if (position >= length) {
                partial_payload += PADDING;
                continue;
            }

            partial_payload += original_payload[position];
        }

        char* c_partial_payload = new char[partial_payload.length() + 1];
        strcpy_s(c_partial_payload, partial_payload.length() + 1, partial_payload.c_str());

        return c_partial_payload;
    }

    char* check_sum(char payload[]) {

        int sum = 0;

        for (int i = 0; i < sizeof(payload); i++) {
            sum += (int)(unsigned char)payload[i];
        }
        stringstream string_stream;
        string_stream << hex << uppercase << sum;

        string hex = string_stream.str();

        // make it usable
        char* c_hex = new char[hex.length() + 1];
        strcpy_s(c_hex, hex.length() + 1, hex.c_str());


        return c_hex;
    }

    char* add_split(char flag, char sequence_number[], char ack_number[], char check_sum[], char active_payload[]) {
        string s_value;
        s_value += flag; // Add the flag
        s_value += SPLIT; // Add the split separator
        s_value += sequence_number; // Add the sequence number
        s_value += SPLIT; // Add the split separator
        s_value += ack_number; // Add the ack number
        s_value += SPLIT; // Add the split separator
        s_value += check_sum; // Add the checksum
        s_value += SPLIT; // Add the split separator
        s_value += active_payload; // Add the active payload

        char* value = new char[s_value.length() + 1];
        strcpy_s(value, s_value.length() + 1, s_value.c_str());
        return value;
    }


    char* format_sequance_number(int sequance_number) {
        string value = to_string(sequance_number);
        while (value.length() < SEQ_ACK_NUM_SIZE)
        {
            value = "0" + value;
        }
        return convert_string_to_char_array(value);
    }

    string* next_seq_and_ack(char* sequance_number) {
        // send SYN ACK back
        int i_seq_numb = convert_char_to_int(sequance_number) + 1; // Make the new sequance number
        int i_ack_numb = i_seq_numb + 1; // next packet

        sequance_number = format_sequance_number(i_seq_numb);
        char* ack_numb = format_sequance_number(i_ack_numb);

        string* out = new string[2];
        out[0] = sequance_number;
        out[1] = ack_numb;

        return out;
        
    }

    string* make_sequance_number(int split_amount) {

        int array_size = split_amount + 5;// the + 5 is to give one to each TCP information (syn,synack..)
        int* sequance_number = new int[array_size];

        int original_number = 0; // in the future we might want to make it random (or not will be here in case because it change nothing)

        // Generate all the needed number
        for (int i = 0; i < array_size; i++) {
            sequance_number[i] = original_number + i;
        }

        string* out = new string[array_size];

        // ensure their length is of the value of the const for SEQ_ACK_NUM_SIZE
        for (int i = 0; i < array_size; i++) {
            string test_value = to_string(sequance_number[i]);
            while (test_value.length() < SEQ_ACK_NUM_SIZE) {
                test_value = "0" + test_value;
            }
            out[i] = test_value;
        }

        return out;
    }

    char* convert_string_to_char_array(string value) {
        char* out = new char[value.length() + 1];
        strcpy_s(out, value.length() + 1, value.c_str());
        return out;
    }

    int convert_char_to_int(char* num) {
        // TODO : add validation with regex that there is only number in there 

        return atoi(num);
    }

    // ============ 


    // === Region Networking ===

    int send_icmp_raw(const char* target_ip, const char* payload_data) {

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed." << std::endl;
            return 1;
        }

        SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock == INVALID_SOCKET) {
            cerr << "Failed to create raw socket: " << WSAGetLastError() << endl;
            WSACleanup();
            return 1;
        }

        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        inet_pton(AF_INET, target_ip, &dest.sin_addr);


        char packet[sizeof(ICMPHeader) + MAXIMUM_PAYLOAD_SIZE]{};

        ICMPHeader* icmp = (ICMPHeader*)packet;
        icmp->type = 8; // Echo request
        icmp->code = 0;
        icmp->id = (uint16_t)GetCurrentProcessId();
        static uint16_t seq = 0;
        icmp->sequence = htons(seq++);

        // Copy payload (max 32 bytes)
        size_t payload_len = strlen(payload_data);
        if (payload_len > MAXIMUM_PAYLOAD_SIZE) payload_len = MAXIMUM_PAYLOAD_SIZE;
        memcpy(packet + sizeof(ICMPHeader), payload_data, payload_len);

        // Compute checksum
        icmp->checksum = 0;
        icmp->checksum = checksum((uint16_t*)packet, sizeof(ICMPHeader) + (int)payload_len);

        int send_result = sendto(sock, packet, sizeof(ICMPHeader) + (int)payload_len, 0,
            (sockaddr*)&dest, sizeof(dest));
        if (send_result == SOCKET_ERROR) {
            cerr << "sendto failed: " << WSAGetLastError() << endl;
            closesocket(sock);
            WSACleanup();
            return 1;
        }

    std:cout << "ICMP packet sent to " << target_ip << " with payload: \"" << payload_data << "\"" << endl;

        closesocket(sock);
        WSACleanup();
        return 0;
    }



    // ============



    // === Region Understanding Payload ==

    /// This allways receive it in this order : 
    /// 0 : flag (char)
    /// 1 : seq number (int)(in a char)
    /// 2 : ack number (int)(in a char)
    /// 3 : checksum (hex)(in a char)
    /// 4 : data (allways consider it string for now)
    void split_reception(char* data) {
        string s_data = data;

        std::vector<std::string> result;
        size_t start = 0;
        size_t end = s_data.find(SPLIT);

        while (end != std::string::npos) {
            result.push_back(s_data.substr(start, end - start));
            start = end + SPLIT.length();
            end = s_data.find(SPLIT, start);
        }

        result.push_back(s_data.substr(start));

        if (result.size() != 5) {
            // Make error handling so random ICMP packet does not destroy the script 
        cout << "[!] ALLERT : The recieved packet does not have the supposed amount of information";
        }
        // Verify flag is properly handled
        if (result[0].size() > 1) {
        cout << "[!] Alert : Malformated packet the first part is longer than 1. : " << result[0] << endl;
        }

        char flag = convert_string_to_char_array(result[0])[0];
        char* seq_num = convert_string_to_char_array(result[1]);
        char* ack_num = convert_string_to_char_array(result[2]);
        char* check_ar = convert_string_to_char_array(result[3]);
        char* payload = convert_string_to_char_array(result[4]);

        switch (flag)
        {
        case SYN:
            start_syn_connection(seq_num, payload);
            break;
        case SYN_ACK:
            syn_ack_received(seq_num, payload);
            break;
        case ACK:
            ack_received(seq_num, payload);
            break;
        case FIN:
            break;
        case FIN_ACK:
            fin_ack_recieved();
            break;
        default:
            cout << "[?] Unknown Flag received. Properly formated packet.";
            break;
        }


        return;
    }

    void start_syn_connection(char* seq_numb, char* payload) {
        string* seq_ack = next_seq_and_ack(seq_numb);




        /*THIS IS NOT GOOD WE NEED TO MAKE A WAY TO KEEP TRACK OF A SPECIFIC SESSION WITH MULTIPLE TCP CONNECTION STOP BEEING DUMB!*/
        active_connection_information["ip"] = ip;
        active_connection_information["last_flag"] = "";

        char* seq = convert_string_to_char_array(seq_ack[0]);
        char* ack = convert_string_to_char_array(seq_ack[1]);
        char* sum = check_sum(payload);
        send_icmp_raw(ip, add_split(SYN_ACK, seq,ack, sum, payload)); // send a SYN ACK packet 

        return;
    }

    void syn_ack_received(char* seq_numb, char* payload) {
        // send ACK back
        string* seq_ack = next_seq_and_ack(seq_numb);

        active_connection_information["ip"] = ip;
        active_connection_information["last_flag"] = SYN;

        send_icmp_raw(ip, add_split(SYN_ACK, convert_string_to_char_array(seq_ack[0]), convert_string_to_char_array(seq_ack[1]), check_sum(payload), payload)); // send a SYN ACK packet 
        return;
    }

    void ack_received(char* seq_numb, char* payload) {
        // Connection waiting information
        // Ensure logic for SYN and FIN to work (we need to know if we are closing or oppening something)

        if (active_connection_information["last_flag"] == to_string(SYN) || active_connection_information["last_flag"] == to_string(SYN_ACK)) {
            active_connection_information["last_flag"] = ACK;

        }

        else if (active_connection_information["last_flag"] == to_string(FIN) || active_connection_information["last_flag"] == to_string(FIN_ACK)) {

        }

        else {
            cout << "[?] Unhandled last flag in the last \"ack received\" function. flag received : " << active_connection_information["last_flag"]  <<endl;
        }



        return;
    }

    void fin_received() {
        // send back fin ack
        return;
    }

    void fin_ack_recieved() {
        // send back ack
        return;
    }

    // ============

public :
    char* ip;
    icmp_tcp(string _ip) {
        ip = convert_string_to_char_array(_ip);
    }



    int test_area()
    {
        // == testing




         //system("pause");



        // ======


        

        char t[] = { "whoami a potato who really like potato for the fun of potato because potato are awsome !" };
        int split_needed = calculate_split(t);
        string* seq_a = make_sequance_number(split_needed);

        for (int i = 0; i < split_needed; i++) {
            char* value = resized_char(t, i);

            char* data = add_split(SYN, convert_string_to_char_array(seq_a[i]), convert_string_to_char_array(seq_a[i]), check_sum(value), value);
            split_reception(data);
            //std:cout << data << endl;
            //send_icmp_raw("127.0.0.1", data);
            delete[] value;
        }


        system("pause");


        return 0;

    }


};



void start_icmp_listener() {



    SOCKET recv_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_socket == INVALID_SOCKET) {
        std::cerr << "[!] Failed to create raw socket: " << WSAGetLastError() << std::endl;
        return;
    }

    // === Bind to local interface (needed on Windows) ===
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0;

    if (bind(recv_socket, (sockaddr*)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
        std::cerr << "[!] bind failed: " << WSAGetLastError() << std::endl;
        closesocket(recv_socket);
        return;
    }

std:cout << "[+] ICMP listener started... Waiting for packets." << std::endl;

    char recv_buf[1024];
    sockaddr_in sender{};
    int sender_len = sizeof(sender);

    while (true) {
        int bytes_received = recvfrom(recv_socket, recv_buf, sizeof(recv_buf), 0, (sockaddr*)&sender, &sender_len);
        if (bytes_received == SOCKET_ERROR) {
            std::cerr << "[!] recvfrom failed: " << WSAGetLastError() << std::endl;
            break;
        }

        unsigned char ip_header_len = (recv_buf[0] & 0x0F) * 4;
        if (bytes_received < ip_header_len + 8) continue;

        const char* icmp_data = recv_buf + ip_header_len;
        const unsigned char icmp_type = icmp_data[0];
        const unsigned char icmp_code = icmp_data[1];

        if (icmp_type != 8 && icmp_type != 0) continue; // Echo request OR reply

        const char* payload = icmp_data + 8;
        int payload_len = bytes_received - ip_header_len - 8;

        std::cout << "\n[ICMP RECEIVED] From: " << inet_ntoa(sender.sin_addr)
            << " | Payload: ";
        std::cout.write(payload, payload_len);
        std::cout << std::endl;
    }

    closesocket(recv_socket);



}



int main() {

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    std::thread listener_thread(start_icmp_listener);
    listener_thread.detach(); // Run in background

    std::this_thread::sleep_for(std::chrono::seconds(1));

    icmp_tcp t = icmp_tcp("127.0.0.1");
    t.test_area();
    return 0;
}


