#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WS2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <IcmpAPI.h>
#include <string>
#include <cstring>

#include <iostream>

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

using namespace std;

// TODO : now we need to split the string it receive to make it at a maximum size of 32.
// We need to find how to make that happen in C++ once this is done we will connect the function that can send data and the one that parse it

//To make a TCP connection we will make a handshake over ICMP between the receiver and the sender to ensure the connection [syn,synack,ack]
// To ensure delivery of every packet it is doable to do a handshake each time or once this is done (or during) we could say how many packet we plan on sending. and use part of the binary to tell the number of packet we are at.
// this could limite the amount of packet we can send but might be acceptable if we use a larger part of the usable size (such as 10 bit) 
// Maybe we could use the answer to the echo ping ? such as the number it received last ?

// we will see this an other day hopefully 

const WORD MAXIMUM_PAYLOAD_SIZE = 32;
const char PADDING = ' '; // if the string finish with white space that is padding


int send_icmp_packet(PCSTR ip, char payload[]) {
    // Create the ICMP context.
    HANDLE icmp_handle = IcmpCreateFile();
    if (icmp_handle == INVALID_HANDLE_VALUE) {
        throw;
    }

    // Parse the destination IP address.
    IN_ADDR dest_ip{};
    if (1 != InetPtonA(AF_INET, ip, &dest_ip)) {
        throw;
    }


    // Reply buffer
    
    constexpr DWORD reply_buf_size = sizeof(ICMP_ECHO_REPLY) + MAXIMUM_PAYLOAD_SIZE + 8;
    unsigned char reply_buf[reply_buf_size]{};

    // Make the echo request.
    DWORD reply_count = IcmpSendEcho(icmp_handle, dest_ip.S_un.S_addr,
        payload, MAXIMUM_PAYLOAD_SIZE, NULL, reply_buf, reply_buf_size, 10000);

    // Return value of 0 indicates failure, try to get error info.
    if (reply_count == 0) {
        auto e = GetLastError();
        DWORD buf_size = 1000;
        WCHAR buf[1000];
        GetIpErrorString(e, buf, &buf_size);
        std::cout << "IcmpSendEcho returned error " << e << " (" << buf << ")" << std::endl;
        return 255;
    }

    const ICMP_ECHO_REPLY* r = (const ICMP_ECHO_REPLY*)reply_buf;
    struct in_addr addr;
    addr.s_addr = r->Address;
    char* s_ip = inet_ntoa(addr);
    std::cout << "Reply from: " << s_ip << ": bytes=" << r->DataSize << " time=" << r->RoundTripTime << "ms TTL=" << (int)r->Options.Ttl << std::endl;

    // Close ICMP context.
    IcmpCloseHandle(icmp_handle);
    return 0;
}

int calculate_split(char original_payload[]) {
    int size = strlen(original_payload); // for now we ignore the null terminator 

    long split = ceil(static_cast<float>(size) / MAXIMUM_PAYLOAD_SIZE); // give us the amount of split we will need 
    cout << "String size is : " << size << endl;
    cout << "Amount of split needed : " << split << endl;

    return split; // error handle latter
}


// Maybe need to reformat to be sur it work but this version 1 should be enough
char* resized_char(char original_payload[], int split_placement) {
    int position_placement = split_placement * MAXIMUM_PAYLOAD_SIZE;
    std::string partial_payload;
    int length = strlen(original_payload);

    for (short i = 0; i < MAXIMUM_PAYLOAD_SIZE; i++) {
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


int main()
{
    char t[] = { "whoami a potato who really like potato for the fun of potato because potato are awsome !" };
    int split_needed = calculate_split(t);

    for (int i = 0; i < split_needed; i++) {
        char* value = resized_char(t, i);
        cout << value << "length: " << strlen(value) << endl;
        send_icmp_packet("127.0.0.1", value);
    }


   
}