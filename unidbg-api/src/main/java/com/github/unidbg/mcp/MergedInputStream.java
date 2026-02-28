package com.github.unidbg.mcp;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;

/**
 * Merges keyboard stdin and piped MCP command input.
 * Reads from whichever stream has available data, prioritizing piped commands.
 */
public class MergedInputStream extends InputStream {

    private final InputStream keyboard;
    private final InputStream pipe;

    public MergedInputStream(InputStream keyboard, InputStream pipe) {
        this.keyboard = keyboard;
        this.pipe = pipe;
    }

    @Override
    public int read() throws IOException {
        while (true) {
            if (pipe.available() > 0) {
                return pipe.read();
            }
            if (keyboard.available() > 0) {
                return keyboard.read();
            }
            try {
                TimeUnit.MILLISECONDS.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
        }
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        while (true) {
            int pipeAvail = pipe.available();
            if (pipeAvail > 0) {
                return pipe.read(b, off, Math.min(len, pipeAvail));
            }
            int kbAvail = keyboard.available();
            if (kbAvail > 0) {
                return keyboard.read(b, off, Math.min(len, kbAvail));
            }
            try {
                TimeUnit.MILLISECONDS.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return -1;
            }
        }
    }

    @Override
    public int available() throws IOException {
        return pipe.available() + keyboard.available();
    }

    @Override
    public void close() throws IOException {
        pipe.close();
        keyboard.close();
    }
}
