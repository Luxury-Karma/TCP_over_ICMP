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
#include <queue>
#include <mutex>
#include <condition_variable>

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

using namespace std;

const std::string SPLIT = "-^|^-";// Use to split the section of the payload
static constexpr WORD SECTION_AMOUNT = 7;

const short FLAG_POSITION= 0; 
const short SEQ_POSITION = 1;
const short ACK_POSITION = 2; 
const short CHECK_SUM_POSITION = 3; 
const short PAYLOAD_POSITION = 4;
const short UID_POSITION = 5;
const short IP_POSITION = 6;


std::queue<std::string> icmp_packet_queue;
std::mutex icmp_mutex;
std::condition_variable icmp_cv;



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
    static constexpr WORD UID = 5;
    static constexpr WORD SPLIT_SIZE = 5;
    

    static constexpr WORD MAXIMUM_PAYLOAD_SIZE = FLAG_SIZE + (SEQ_ACK_NUM_SIZE * 2) + CHECK_SUM_SIZE + ACTUAL_PAYLOAD_SIZE + UID + (SPLIT_SIZE * 5); // total size of the payload including separator

    static constexpr char PADDING = ' '; // if the string finish with white space that is padding

    // TCP flags (lets do hand shake and all ! 
    static constexpr char SYN = 's';
    static constexpr char ACK = 'a';
    static constexpr char SYN_ACK = 'z';
    static constexpr char FIN = 'f';
    static constexpr char FIN_ACK = 'q';
    static constexpr char PAYLOAD_FLAG = 'p';
    const std::string SPLIT = "-^|^-";// Use to split the section of the payload


    

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


    char* check_sum(const char payload[], int length) {
        int sum = 0;
        for (int i = 0; i < length; i++) {
            sum += (unsigned char)payload[i];
        }

        std::stringstream string_stream;
        string_stream << std::hex << std::uppercase << sum;
        std::string hex = string_stream.str();

        char* c_hex = new char[hex.length() + 1];
        strcpy_s(c_hex, hex.length() + 1, hex.c_str());
        return c_hex;
    }

    char* add_split(char flag, char sequence_number[], char ack_number[], char check_sum[], char active_payload[]) {

        char* a_payload = padding_payload(active_payload);

        string s_value;
        s_value += flag; // Add the flag
        s_value += SPLIT; // Add the split separator
        s_value += sequence_number; // Add the sequence number
        s_value += SPLIT; // Add the split separator
        s_value += ack_number; // Add the ack number
        s_value += SPLIT; // Add the split separator
        s_value += check_sum; // Add the checksum
        s_value += SPLIT; // Add the split separator
        s_value += a_payload; // Add the active payload
        s_value += SPLIT; // Add the split separator
        s_value += active_connection_information["uid"]; // add the ID of the connection

        char* value = new char[s_value.length() + 1];
        strcpy_s(value, s_value.length() + 1, s_value.c_str());

        cout << "payload created : " << value << endl;

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
    
    char* padding_payload(char* payload) {
        string temp = payload;
        
        while (temp.size() < ACTUAL_PAYLOAD_SIZE) {
            temp = temp + PADDING;
        }

        return convert_string_to_char_array(temp);
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

    bool is_check_sum_okay(char* payload_data, char* received_checksum) {
        char* sum = check_sum(payload_data, strlen(payload_data)); 
        bool result = strcmp(sum, received_checksum) == 0;
        delete sum;
        return result;

    }

    // ============



    // === Region Understanding Payload ==

    string remove_payload_padding(string payload) {
        int padding_finish_position = payload.size() - 1;
        // Find where the padding finish
        for (int i = payload.size() - 1; i >= 0; i--) {
            
            if (payload[i] == PADDING) {
                continue;
            }

            padding_finish_position = i;
            break;

        }

        string value = "";

        for (int i = 0; i <= padding_finish_position; i++) {
            value = value + payload[i];
        }

        return value;
    }
    
    void syn_received(char* seq_numb, char* payload) {
        string* seq_ack = next_seq_and_ack(seq_numb);

        active_connection_information["last_flag"] = "";

        char* seq = convert_string_to_char_array(seq_ack[0]);
        char* ack = convert_string_to_char_array(seq_ack[1]);
        char* sum = check_sum(payload, strlen(payload));
        send_icmp_raw(convert_string_to_char_array(active_connection_information["ip"]), add_split(SYN_ACK, seq, ack, sum, payload)); // send a SYN ACK packet 

        return;
    }

    void syn_ack_received(char* seq_numb, char* payload) {
        // send ACK back
        string* seq_ack = next_seq_and_ack(seq_numb);

        active_connection_information["last_flag"] = SYN_ACK;

        send_icmp_raw(convert_string_to_char_array(active_connection_information["ip"]), add_split(ACK, convert_string_to_char_array(seq_ack[0]), convert_string_to_char_array(seq_ack[1]), check_sum(payload, strlen(payload)), payload)); // send a SYN ACK packet 
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

    void fin_received(char* seq_numb, char* payload) {
        // send back fin ack
        string* seq_ack = next_seq_and_ack(seq_numb);
        active_connection_information["last_flag"] = FIN;
        send_icmp_raw(convert_string_to_char_array(active_connection_information["ip"]), add_split(FIN_ACK, convert_string_to_char_array(seq_ack[0]), convert_string_to_char_array(seq_ack[1]), check_sum(payload,strlen(payload)), payload)); // send a SYN ACK packet 
        return;
    }

    void fin_ack_recieved(char* seq_numb, char* payload) {
        // send back ack
        string* seq_ack = next_seq_and_ack(seq_numb);
        active_connection_information["last_flag"] = FIN_ACK;
        send_icmp_raw(convert_string_to_char_array(active_connection_information["ip"]), add_split(ACK, convert_string_to_char_array(seq_ack[0]), convert_string_to_char_array(seq_ack[1]), check_sum(payload, strlen(payload)), payload)); // send a SYN ACK packet 
        return;

        return;
    }

    // ============



public :

    /* TODO: make this more good */
    map<string, string> active_connection_information;
    /* THIS HERE !!! */

    icmp_tcp(string _ip) {
        active_connection_information["ip"] = _ip;
        active_connection_information["uid"] = "00"; // TODO when we make the logic for the ID we need to make logic here
        active_connection_information["last_flag"] = ""; // initialise it


    }


    

    bool start_connection() {

        char payload[] = {"hello"};
        char* seq_num = format_sequance_number('0');
        char* ack_num = format_sequance_number('1');
        char* check = check_sum(payload,strlen(payload));

        char* data = add_split(SYN, seq_num, ack_num, check, payload);

        try {
            send_icmp_raw(convert_string_to_char_array(active_connection_information["ip"]), data);
        }
        catch (int e) {
            cout << "[!] Error sending the ICMP packet in the start connection error : " << e;
            return false; // this mean it wasn't able to send the packet 
        };


        return true; // this mean it was able to send the packet
    }


    void act_on_reception(string* info_packet) {
        char flag = info_packet[FLAG_POSITION][0];

        info_packet[PAYLOAD_POSITION] = remove_payload_padding(info_packet[PAYLOAD_POSITION]);

        if (!is_check_sum_okay(convert_string_to_char_array(info_packet[PAYLOAD_POSITION]), convert_string_to_char_array(info_packet[CHECK_SUM_POSITION]))) {
            cout << "[?] Check sum did not match. Packet got corrupted payload " << info_packet[PAYLOAD_POSITION];
            return;
        }
        
        switch (flag)
        {
        case SYN:
            syn_received(convert_string_to_char_array(info_packet[SEQ_POSITION]), convert_string_to_char_array(info_packet[PAYLOAD_POSITION]));
            break;
        case SYN_ACK:
            syn_ack_received(convert_string_to_char_array(info_packet[SEQ_POSITION]), convert_string_to_char_array(info_packet[PAYLOAD_POSITION]));
            break;
        case ACK:
            ack_received(convert_string_to_char_array(info_packet[SEQ_POSITION]), convert_string_to_char_array(info_packet[PAYLOAD_POSITION]));
            break;
        case FIN:
            fin_received(convert_string_to_char_array(info_packet[SEQ_POSITION]), convert_string_to_char_array(info_packet[PAYLOAD_POSITION]));
            break;
        case FIN_ACK:
            fin_ack_recieved(convert_string_to_char_array(info_packet[SEQ_POSITION]), convert_string_to_char_array(info_packet[PAYLOAD_POSITION]));
            break;
        case PAYLOAD_FLAG:
            break;
        default:
            cout << "[?] The packet did not have a known flag to act on : " << flag << endl;
            break;
        }
        
    }

};

/// This allways receive it in this order : 
    /// 0 : flag (char)
    /// 1 : seq number (int)(in a char)
    /// 2 : ack number (int)(in a char)
    /// 3 : checksum (hex)(in a char)
    /// 4 : data (allways consider it string for now)
    /// 5 : the ip where the packet is from
string* split_reception(string data) {

    std::vector<std::string> result;
    size_t start = 0;
    size_t end = data.find(SPLIT);

    while (end != std::string::npos) {
        result.push_back(data.substr(start, end - start));
        start = end + SPLIT.length();
        end = data.find(SPLIT, start);
    }

    result.push_back(data.substr(start));

    if (result.size() != SECTION_AMOUNT) {
        // Make error handling so random ICMP packet does not destroy the script 
        cout << "[!] ALLERT : The recieved packet does not have the supposed amount of information";
    }
    // Verify flag is properly handled
    if (result[0].size() > 1) {
        cout << "[!] Alert : Malformated packet the first part is longer than 1. : " << result[0] << endl;
    }
    /*
    flag = result[0];
    seq_num = result[1];
    ack_num = result[2];
    check_ar = result[3];
    payload = result[4];
    ip = result[5];
    */
    string* out = new string[SECTION_AMOUNT];

    for (int i = 0; i < SECTION_AMOUNT; i++) {
        out[i] = result[i];
    }

    return out;
}


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

        std::string payload_str(payload, payload_len); // make the data readable without all of the padding


        // === Debug for the reception of the packet

        std::cout << "\n[ICMP RECEIVED] From: " << inet_ntoa(sender.sin_addr) << " | Payload: " << payload_str;

        // === send the packet to the main thread.
        std::lock_guard<std::mutex> lock(icmp_mutex);
        string full_payload = payload_str + SPLIT + inet_ntoa(sender.sin_addr);
        icmp_packet_queue.emplace(full_payload);
        icmp_cv.notify_one(); // Notify main thread

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
    std::vector<icmp_tcp> all_active_connection;

    

    icmp_tcp t = icmp_tcp("127.0.0.1");

    t.start_connection();
    
    all_active_connection.push_back(t);


    while (true) {
        
        
        std::unique_lock<std::mutex> lock(icmp_mutex);
        icmp_cv.wait(lock, [] { return !icmp_packet_queue.empty(); });

        std::string packet = icmp_packet_queue.front();
        icmp_packet_queue.pop();
        lock.unlock(); // Unlock before processing

        std::cout << "[MAIN THREAD] Received packet payload: " << packet << std::endl;

        string* data = split_reception(packet);

        cout << "received data from: " << data[IP_POSITION] << " with ID : " << data[UID_POSITION] << endl;

        

        for (int i = 0; i < all_active_connection.size(); i++) {
            icmp_tcp connection = all_active_connection[i];
            bool uid = connection.active_connection_information["uid"] == data[UID_POSITION];
            bool ip = data[IP_POSITION] == connection.active_connection_information["ip"];
            if (!ip && !uid) {
                continue;
            }

            connection.act_on_reception(data);
        }


    }


    return 0;
}


