package com.ammaraskar.coverageagent;

import android.util.Log;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Coverage map algorithm based on https://lcamtuf.coredump.cx/afl/technical_details.txt
 */
@SuppressWarnings("unused")
public class Instrumentation {
    private static final int COVERAGE_MAP_SIZE = 64 * 1024;
    private static byte[] coverageMap = new byte[COVERAGE_MAP_SIZE];

    private static int previousBlock = 0;

    // Initialize a tcp socket so a dump and reset of the coverage map can be requested.
    static {
        Instrumentation.startServer();
    }

    private static void startServer() {
        ServerSocket serverSocket;
        try {
            serverSocket = new ServerSocket(6249);
        } catch (IOException e) {
            Log.e("coverage", "Failed to initialize unix socket");
            e.printStackTrace();
            return;
        }

        Thread listener = new Thread(() -> {
            Log.i("ammaraskar", "Server socket initialized, in thread!");
            while (true) {
                try {
                    acceptConnection(serverSocket);
                } catch (IOException e) {
                    Log.e("coverage", "Failed to accept on unix socket");
                    e.printStackTrace();
                }
            }
        });
        listener.start();
    }

    private static void acceptConnection(ServerSocket serverSocket) throws IOException {
        Socket socket = serverSocket.accept();

        // Read command from socket, 'd' or 'r'
        while (true) {
            int command = socket.getInputStream().read();
            if (command == 'd') {
                // dump
                socket.getOutputStream().write(coverageMap);
            } else if (command == 'r') {
                // reset
                coverageMap = new byte[COVERAGE_MAP_SIZE];
            } else if (command == -1) {
                break;
            }
        }
    }


    public static void reachedBlock(int blockId) {
        coverageMap[(blockId ^ previousBlock) % COVERAGE_MAP_SIZE]++;
        previousBlock = blockId >> 1;

        /*
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        StackTraceElement caller = stackTrace[3];

        Log.i("instrumentation", "Hi I am in reached, my caller is " + caller.toString());
         */
    }
}
