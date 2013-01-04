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

public class PlainPasswordFile implements IPasswordStore{
    private String mPwdPath = "";
    private Properties mPwdStore;
    private static final String PASSWORD_WRITER_HEADER = "";

    public PlainPasswordFile() {
    }

    public void init(String pwdPath)
	throws IOException
    {
	mPwdStore = new Properties();
	// initialize mPwdStore
	mPwdPath = pwdPath;

	FileInputStream file = new FileInputStream(mPwdPath);
	mPwdStore.load(file);
    }

    public String getPassword(String tag) {
	return (String) mPwdStore.getProperty(tag);
    }

    // return an array of String-based tag
    public Enumeration getTags() {
	return mPwdStore.propertyNames();
    }

    public Object putPassword(String tag, String password) {
        return mPwdStore.setProperty(tag, password);
    }

    public void commit()
        throws IOException, ClassCastException, NullPointerException
    {
        FileOutputStream file = new FileOutputStream(mPwdPath);
        mPwdStore.store(file, PASSWORD_WRITER_HEADER);
    }
}
