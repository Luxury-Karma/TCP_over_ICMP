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

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

using namespace std;


const WORD FLAG_SIZE = 1; // Flag size in byte
const WORD SEQ_ACK_NUM_SIZE = 8;  // sequance and ackk in byte ( real size is x2 ) 
const WORD CHECK_SUM_SIZE = 3; // Check sum size in byte 
const WORD ACTUAL_PAYLOAD_SIZE = 100; // Data size we are sending 
const WORD SPLIT_SIZE = 5;

const WORD MAXIMUM_PAYLOAD_SIZE = FLAG_SIZE+(SEQ_ACK_NUM_SIZE*2)+CHECK_SUM_SIZE+ACTUAL_PAYLOAD_SIZE+(SPLIT_SIZE*4); // total size of the payload including separator

const char PADDING = ' '; // if the string finish with white space that is padding

// TCP flags (lets do hand shake and all ! 
const char SYN = 's';
const char ACK = 'a';
const char SYN_ACK = 'z';
const char FIN = 'f';
const char FIN_ACK = 'q';


const string SPLIT = "-^|^-"; // Use to split the section of the payload


struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

// Compute checksum for ICMP packet
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
	strcpy_s(value,s_value.length()+1, s_value.c_str());
    return value;
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

    cout << "ICMP packet sent to " << target_ip << " with payload: \"" << payload_data << "\"" << endl;

    closesocket(sock);
    WSACleanup();
    return 0;
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

    std::cout << "[+] ICMP listener started... Waiting for packets." << std::endl;

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

// ============

int main()
{
    // == testing
	
    string* value = make_sequance_number(10);

     system("pause");



    // ======


    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    std::thread listener_thread(start_icmp_listener);
    listener_thread.detach(); // Run in background

    std::this_thread::sleep_for(std::chrono::seconds(1));

    char t[] = { "whoami a potato who really like potato for the fun of potato because potato are awsome !" };
    int split_needed = calculate_split(t);

    for (int i = 0; i < split_needed; i++) {
        char* value = resized_char(t, i);
        send_icmp_raw("127.0.0.1", value);
        delete[] value;
    }

    
    system("pause");


    return 0;
   
}