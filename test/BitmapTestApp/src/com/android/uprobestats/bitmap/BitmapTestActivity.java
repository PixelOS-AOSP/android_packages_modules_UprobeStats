/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.uprobestats.bitmap;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.BitmapFactory;

public class BitmapTestActivity extends Activity {
    private static final String TAG = BitmapTestActivity.class.getSimpleName();
    android.graphics.Bitmap longLivedBitmap;

    @Override
    protected void onStart() {
        super.onStart();
        android.graphics.Bitmap.createBitmap(100, 100,
                android.graphics.Bitmap.Config.ARGB_8888);
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inScaled = false; // Disable scaling
        longLivedBitmap =
                android.graphics.BitmapFactory.decodeResource(
                        getResources(), R.drawable.icon1, options);

        Runnable myTask =
                () -> {
                    android.graphics.Bitmap png2 =
                            android.graphics.BitmapFactory.decodeResource(
                                    getResources(), R.drawable.icon1, options);
                    android.graphics.Bitmap scaledBitmap =
                            android.graphics.Bitmap.createScaledBitmap(png2, 321, 321, true);
                    png2 = null;
                };

        // Create and start the thread
        Thread myThread = new Thread(myTask);
        myThread.start();

        // Optionally, wait for the thread to finish
        try {
            myThread.join(); // Wait for myThread to terminate
        } catch (InterruptedException e) {
        }
    }
}
