Chat System

TCP Chat Client and Interactive Web Frontend

Overview

This project implements a TCP based chat system using C++ socket programming. Multiple clients can connect to a central server, communicate in real time, and execute commands such as LOGIN, SEND, BROADCAST, BLOCK, UNBLOCK, LIST, and REFRESH.

In addition to the terminal based system, a custom web frontend was developed to provide an interactive and visual representation of client communication.

Tech Stack

Backend
C++
BSD Sockets using TCP
select system call for I O multiplexing

Frontend
HTML CSS JavaScript
Dynamic DOM manipulation
Terminal style user interface

Features

Networking Backend
Multi client TCP server
Concurrent client handling using select
Full duplex communication
Client tracking including IP address port and hostname
Direct messaging between clients
Broadcast messaging to all clients
Block and unblock functionality
Command parsing and protocol logging

Interactive Frontend
Terminal inspired interface
Live client list with selection and status indicators
Broadcast and unicast messaging modes
Typing indicator simulation
Toast notifications for actions and errors
Protocol log display
Double click to select chat targets
Character limit tracking for messages

How It Works

Backend
The server listens for incoming TCP connections and maintains a list of active clients. Using select it can handle multiple clients without using threads. Commands received from clients are parsed and executed. Messages are routed to the correct destination and blocked users are prevented from sending messages.

Frontend
The frontend acts as a visual simulation layer. It mimics client behavior, simulates message sending and receiving, and provides a graphical interface for interacting with the system.

Note The frontend is not directly connected to the C++ backend and is used for demonstration and visualization purposes.
