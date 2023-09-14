package com.ammaraskar.coverageagent;

import android.util.Log;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
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

    private static String traceFile = null;

    private static boolean synchronization = false;

    // Initialize a tcp socket so a dump and reset of the coverage map can be requested.
    static {
        Instrumentation.startServer();
    }

    private static void waitForIdle() {
        // Get the ActivityThread class
        Class activityThreadClass = null;
        try {
            activityThreadClass = Class.forName("android.app.ActivityThread");
            Method method = activityThreadClass.getMethod("waitForIdle");

            method.invoke(null);
        } catch (ClassNotFoundException | IllegalAccessException |
                 NoSuchMethodException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    private static void activateSynchronization() {
        // Get the ActivityThread class
        Class activityThreadClass = null;
        try {
            activityThreadClass = Class.forName("android.app.ActivityThread");
            Field field = activityThreadClass.getField("synchronizing");

            field.setBoolean(null, true);

            synchronization = true;
        } catch (ClassNotFoundException | IllegalAccessException | NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    private static void deactivateSynchronization() {
        // Get the ActivityThread class
        Class activityThreadClass = null;
        try {
            activityThreadClass = Class.forName("android.app.ActivityThread");
            Field field = activityThreadClass.getField("synchronizing");

            field.setBoolean(null, false);

            synchronization = false;
        } catch (ClassNotFoundException | IllegalAccessException | NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    private static void startServer() {
        ServerSocket serverSocket;
        try {
            serverSocket = new ServerSocket(6249);
            serverSocket.setReuseAddress(true);
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
        Log.i("coverage", "Accepted connection from " + socket.getInetAddress().toString());
        socket.setTcpNoDelay(true);

        Log.i("coverage", "Handling commands");

        // Read command from socket, 'd', 'r', 't', or 's'
        while (true) {
            int command = socket.getInputStream().read();
            Log.i("coverage", "Received command: " + command);
            switch (command) {
                case 'd':
                    // dump
                    if (synchronization) {
                        Instrumentation.waitForIdle();
                    }
                    socket.getOutputStream().write(coverageMap);
                    break;
                case 'r':
                    // reset
                    coverageMap = new byte[COVERAGE_MAP_SIZE];
                    socket.getOutputStream().write((byte)'d');
                    break;
                case 't':
                    // trace native
                    int trace_arg = socket.getInputStream().read();
                    if (trace_arg == 's') {
                        // start
                        // Read the trace file name (until \n)
                        StringBuilder sb = new StringBuilder();
                        while (true) {
                            int c = socket.getInputStream().read();
                            if (c == '\n') {
                                break;
                            }
                            sb.append((char)c);
                        }
                        traceFile = sb.toString();
                        Log.i("coverage", "Starting trace to " + traceFile);
                    } else if (trace_arg == 'e') {
                        // end
                        traceFile = null;
                    }
                    break;
                case 's':
                    // synchronization
                    int sync_arg = socket.getInputStream().read();
                    if (sync_arg == 's') {
                        // start synchronization
                        Log.i("coverage", "Activating synchronization");
                        activateSynchronization();
                    } else if (sync_arg == 'e') {
                        // end synchronization
                        Log.i("coverage", "Deactivating synchronization");
                        deactivateSynchronization();
                    }
                    break;
                case 'w':
                    // wait for idle
                    if (synchronization) {
                        Instrumentation.waitForIdle();
                    }
                    socket.getOutputStream().write((byte)'d');
                    break;

                case -1:
                    return;
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
