# NetworkAnalysis
This program creates a graph from a route of IPs from source to target IP.
The combinedFiles folder has an example of the format of the file. The first line is the target IP. Next IPs are the jumps between IPs until reach the target IP.
The program also creates a subgraph of the most common route between routes in each file of the same domain.
# Specific Library
This program requires to install the ipwhois version 0.10.3
pip install ipwhois==0.10.3
