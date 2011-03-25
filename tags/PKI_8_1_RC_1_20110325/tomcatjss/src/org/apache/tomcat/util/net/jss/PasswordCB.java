/* BEGIN COPYRIGHT BLOCK
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK */

package org.apache.tomcat.util.net.jss;

import java.util.Properties;
import java.io.*;
import java.util.*;
import org.mozilla.jss.util.*;
import com.redhat.nuxwdog.*;

public class PasswordCB implements PasswordCallback {

    private IPasswordStore mPasswordStore = null;
    private boolean mStartedByWD = false;
    private int mSerial = 0;

    public PasswordCB(String pwdPath, String pwdClass, boolean startedByWD) 
        throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        if (pwdClass != null) {
            try {
                mPasswordStore = (IPasswordStore)Class.forName(pwdClass).newInstance();
                mPasswordStore.init(pwdPath);
            } catch (IOException io) {
                // Error in reading file at pwdPath 
                // This might be because the file has been removed for security reasons.
            }
        }
        mStartedByWD = startedByWD;
    }

    public Password getPasswordAgain(PasswordCallbackInfo info) 
      throws PasswordCallback.GiveUpException  {
        String pwd = "";
        Password pw = null;
        String tokenName = info.getName();
        String tag = "";

        if (tokenName == null) {
            throw new PasswordCallback.GiveUpException("tokenName is null");
        }

        if (tokenName.equals("Internal Key Storage Token")) {
            tag = "internal";
        } else {
            tag = "hardware-" + tokenName;
        }           

        if (!mStartedByWD) {
            throw new PasswordCallback.GiveUpException(
                "Password for " + tag + " not found in password.conf, and server not started by nuxwdog");
        } 

        mSerial++;
        pwd = WatchdogClient.getPassword("Please provide password for " + tag + ":", mSerial);
        mPasswordStore.putPassword(tag, pwd);

        return new Password(pwd.toCharArray());
    }

    public Password getPasswordFirstAttempt(PasswordCallbackInfo info)
     throws PasswordCallback.GiveUpException  {
        String pwd = "";
        Password pw = null;
        String tokenName = info.getName();
        String tag = "";

        if (tokenName == null) {
            throw new PasswordCallback.GiveUpException("tokenName is null");
        }

        if (tokenName.equals("Internal Key Storage Token")) {
            tag = "internal";
        } else {
            tag = "hardware-" + tokenName;
        }
 
        pwd = mPasswordStore.getPassword(tag);
        
        if  (pwd == null) {
            // password not in password.conf
            if (!mStartedByWD) {
                throw new PasswordCallback.GiveUpException(
                    "Password for " + tag + " not found in password.conf, and server not started by nuxwdog");
            }
            pwd = WatchdogClient.getPassword("Please provide password for " + tag + ":", mSerial);
            mPasswordStore.putPassword(tag, pwd);
        }

        return new Password(pwd.toCharArray());
    } 
}
