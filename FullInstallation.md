# Full Dev Installation for Volatility 2.0 #

This guide is for people who want a full development installation of Volatility 2.0 (for example to write your own plugins or explore the source code).  If you just want to quickly get started with using Volatility, there are standalone executables and installers available in the "[downloads section](https://code.google.com/p/volatility/downloads/list)".



## Installation Prerequisites ##

In order to use Volatility, you will need to install a few prerequisite programs and packages.

Prerequisites
  * Python 2.6 or greater, but not Python 3.0 [Python 2.6](http://python.org/download/releases/) will be used in this guide
  * [Distorm](http://code.google.com/p/distorm/downloads/list) (Malware Plugins, Volshell)
  * [Yara](http://code.google.com/p/yara-project/downloads/list) (Malware Plugins)
  * [PyCrypto](http://gitweb.pycrypto.org/?p=crypto/pycrypto-2.0.x.git;a=summary) (Core)
  * Subversion Client.  We recommend [TortoiseSVN](http://tortoisesvn.tigris.org) for Windows
  * [7zip](http://www.7-zip.org/) or an application that can unzip zip and gzip files
  * [MinGW](http://sourceforge.net/projects/mingw/files/Automated%20MinGW%20Installer/mingw-get-inst/mingw-get-inst-20101030/) or other C Compiler (for compiling Pycrypto library)

## Windows Installation ##

This covers how to install Volatility 2.0 on Windows.

### Python Installation ###

In order to use Volatility, you must first install Python. You should get version 2.6 for Windows. When you download the file, double-click to install and you will see the following security message. Just click Run.

<img src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVKqlik0--I/AAAAAAAAAwU/vc5-9jiOrZo/1.png'>

Choose the appropriate install options. Most likely you will want to install for all users on the<br>
machine:<br>
<br>
<img width='400' height='270' src='https://lh6.googleusercontent.com/_55uSCYxbQ8M/TVKqmUkmqII/AAAAAAAAAwY/Q8f9ObHdn0w/2.png'>

The installer will ask you where you would like to install the Python files, the default under C:\Python26 should be fine:<br>
<br>
<img width='400' height='280' src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVKqm-EPLII/AAAAAAAAAwc/W0FdiOoD7is/3.png'>

The installer will then give you the option for more advanced install options. Unless you know what you are doing, it will be best to leave all options enabled:<br>
<br>
<img width='400' height='280' src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVKqmycrsKI/AAAAAAAAAwg/TyOmq97-MDo/4.png'>

On Vista/Windows7 you may have to confirm that you want to install:<br>
<br>
<img width='370' height='250' src='https://lh6.googleusercontent.com/_55uSCYxbQ8M/TVKqnfoGkXI/AAAAAAAAAwk/LWq38VL5vMc/5.png'>

Hit “Next” and Python will now install. Hit “Finish” when installation completes:<br>
<br>
<img width='400' height='280' src='https://lh3.googleusercontent.com/_55uSCYxbQ8M/TVKqyxWVhqI/AAAAAAAAAwo/TkK_w8a6TO8/6.png'>

<img width='400' height='280' src='https://lh3.googleusercontent.com/_55uSCYxbQ8M/TVKqzej_mUI/AAAAAAAAAws/A7rVWnYkPXU/7.png'>

<h4>Setting Environment Variables</h4>

After Python is installed, you should make sure that the Python extensions are registered. If you have a regular start menu, click on start and then right click on “Computer” and choose properties.  If you have the classic start menu, just right click on “My Computer” and choose properties.<br>
<br>
<img width='400' height='250' src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVK41X4ZnRI/AAAAAAAAAw0/99TMpPkk-hg/0.jpg'>


If you have Windows 7 you will see the following screen.  Choose "Advanced System Settings".  You should see the following (some personal details removed):<br>
<br>
<img width='400' height='400' src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVK67_F3wOI/AAAAAAAAAxQ/9wDMHsDcT6k/s640/1.jpg'>

Make sure you are on the "Advanced" tab and choose "Environmental Variables":<br>
<br>
<img width='270' height='400' src='https://lh3.googleusercontent.com/_55uSCYxbQ8M/TVK41oIOyiI/AAAAAAAAAw8/NRRSBCkAF-E/2.jpg'>

On the next screen find the "Path" variable and click "Edit":<br>
<br>
<img width='270' height='400' src='https://lh4.googleusercontent.com/_55uSCYxbQ8M/TVK418SCMeI/AAAAAAAAAxA/4km0Lnk3PTc/3.png'>

Click on the text and scroll all the way to the end.  Append the path of our Python installation to the end of the existing Path variable. Where it says “Variable Value” go to the end of the line and add the following:<br>
<pre><code>;C:\Python26<br>
</code></pre>
The semicolon separates our new Path location from the current values. If the location of your Python installation is different from the above, type the appropriate folder location instead.<br>
<br>
<img src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVK42A7uUhI/AAAAAAAAAxE/yA8twb6hkMI/5.jpg'>

Now we are ready to test that we have set up everything correctly. Open a command prompt by clicking on the "Start Menu" and clicking on "Run".  For Windows 7, click "Start" and type "cmd" in the search text box and hit "Enter":<br>
<br>
<img width='270' height='400' src='https://lh3.googleusercontent.com/_55uSCYxbQ8M/TVLE-Z03hHI/AAAAAAAAAxc/YnkqyU25rUo/8.jpg'>

Type "python" into the command prompt.  You should then see the Python header and command prompt >>>  Type "quit()" to exit.  If this works, Python is installed correctly.<br>
<br>
<img width='450' height='250' src='https://lh6.googleusercontent.com/_55uSCYxbQ8M/TVLE-jONBVI/AAAAAAAAAxg/N1k72j0BFbE/10.png'>

<h3>Installing Dependencies</h3>


<h4>Installing MinGW</h4>

Occasionally you will need a C/C++ compiler in order to install Python libraries.  If you install Distorm3 or Pycrypto from source, you will need a compiler.  Download the compiler from the <a href='http://sourceforge.net/projects/mingw/files/Automated%20MinGW%20Installer/mingw-get-inst/mingw-get-inst-20101030/'>Sourceforge</a> site.  Make sure you get the "ming-get-inst" installer as shown below:<br>
<br>
<img width='550' height='250' src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVLT6Y753BI/AAAAAAAAAx4/mR34Go3_kms/1.jpg'>

Double click the installer.  You should see the following picture.  Hit Next to continue.<br>
<br>
<img width='450' height='280' src='https://lh6.googleusercontent.com/_55uSCYxbQ8M/TVLT6R76xgI/AAAAAAAAAx8/9o1jGaZplqE/2.png'>

If you are running as Administrator you will see the following screen.  Just hit Next.<br>
<br>
<img width='450' height='280' src='https://lh3.googleusercontent.com/_55uSCYxbQ8M/TVLT6n_CESI/AAAAAAAAAyA/mHVU9Ak3X94/3.png'>

You will have a choice to install the latest MinGW build or prepackaged binaries.<br>
<br>
<img width='450' height='280' src='https://lh3.googleusercontent.com/_55uSCYxbQ8M/TVLT64VhyhI/AAAAAAAAAyE/ialoUjmYAWY/4.png'>

Accept the agreement.<br>
<br>
<img width='450' height='280' src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVLT65ovpTI/AAAAAAAAAyI/H0i0f-chxPA/5.png'>

Choose a location to install MinGW.<br>
<br>
<img width='450' height='280' src='https://lh6.googleusercontent.com/_55uSCYxbQ8M/TVLUEt0hGsI/AAAAAAAAAyM/E1RtoCiEOw0/6.png'>

Keep accepting defaults until you get to the "Select Components" screen.  Here you will need to make sure you have at least the C++ compiler checked as well as "MSYS Basic System" so you will have the "make" utility.<br>
<br>
<img width='450' height='280' src='https://lh6.googleusercontent.com/_55uSCYxbQ8M/TVLUE9HcoeI/AAAAAAAAAyU/btBayTL2qUI/8.jpg'>

Hit Next.  A black command prompt may appear as things are installing; just ignore it.  If all goes well you will see the "Finish" screen.  Just hit "Finish".<br>
<br>
<img width='450' height='280' src='https://lh4.googleusercontent.com/_55uSCYxbQ8M/TVLUFazQSkI/AAAAAAAAAyc/BDKXXAUDXZk/10.png'>

Add the "bin" directory of MinGW to your path like you did for Python.  If you accepted the default installation directory the text to add would be:<br>
<br>
<pre><code>;C:\MinGW\bin<br>
</code></pre>

<img src='https://lh6.googleusercontent.com/_55uSCYxbQ8M/TVLULRCmb8I/AAAAAAAAAyg/rEbyB_zYfw4/11.jpg'>

You can test that this works by typing "gcc" plus "Enter" at the command line.  You should see "gcc: no input files" if your path variable is set up correctly:<br>
<br>
<img src='https://lh4.googleusercontent.com/_55uSCYxbQ8M/TVLULvAPNuI/AAAAAAAAAyk/GbgI4oZ_HWk/12.png'>



<h4>Installing Pycrypto</h4>

If you do not have a C compiler like MinGW installed, you can install a precompiled version of Pycrypto from <a href='http://www.voidspace.org.uk/python/modules.shtml#pycrypto'>www.voidspace.org.uk</a>.  If you installed MinGW as above you can install Pycrypto as follows.<br>
<br>
To install from source, first go to the <a href='http://gitweb.pycrypto.org/?p=crypto/pycrypto-2.0.x.git;a=summary'>Pycrypto</a> repository page.  You can download a snapshot as a gzip file:<br>
<br>
<img src='https://lh6.googleusercontent.com/_55uSCYxbQ8M/TVLe8rfhktI/AAAAAAAAAys/8MZdUoSYRDo/1.jpg'>

If you have 7zip installed, right click on the downloaded file and choose open 7zip->Open Archive:<br>
<br>
<img src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVLe85BHYoI/AAAAAAAAAyw/WfuAdwlC3QE/2.jpg'>

Double click the tar file inside and click the "Extract" button.<br>
<br>
<img src='https://lh4.googleusercontent.com/_55uSCYxbQ8M/TVLe9F_d4qI/AAAAAAAAAy0/vIoSu9teZRY/3.jpg'>

Choose a location to extract the folder to:<br>
<br>
<img width='450' height='280' src='https://lh6.googleusercontent.com/_55uSCYxbQ8M/TVLe9f5CgzI/AAAAAAAAAy4/mGCt9jcOfM8/4.png'>

Once the folder is extracted, open the command prompt and change directory into that folder.  In this case, the folder was extracted onto the Desktop, so the command issued is:<br>
<br>
<pre><code>cd Desktop\pycrypto-2.0.x<br>
</code></pre>

Once inside you can issue a "dir" command to make sure you have all the files, including "setup.py"<br>
<br>
<img width='450' height='250' src='https://lh3.googleusercontent.com/_55uSCYxbQ8M/TVLe9rg6WxI/AAAAAAAAAy8/P6_zwZQTjlo/5.png'>

Type the following commands to install (wait until the first one finishes before typing the second one):<br>
<br>
<pre><code>python setup.py build -c mingw32<br>
python setup.py install<br>
</code></pre>

As long as you don't see any errors Pycrypto should be installed correctly.<br>
<br>
<br>
<br>
<h4>Installing Distorm3</h4>

Distorm3 is used by several Malware plugins as well as the Core Volshell plugin.  It's easiest to install the precompiled library for Python 2.6, which is the method shown here.  Go to the Distorm Google Code page and download the distorm3-1.0.win32.zip which contains the library for Python 2.6.  Unzip the file and navigate into the Python26\Lib\site-packages directory:<br>
<br>
<img src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVLIfzynL2I/AAAAAAAAAxo/7U4hXJvnmaY/1.png'>

Copy all contents into your Python 2.6 library location, in this case C:\Python26\Lib\site-packages<br>
<br>
<img src='https://lh6.googleusercontent.com/_55uSCYxbQ8M/TVLIgKMDlAI/AAAAAAAAAxs/uh7Zo-ZIEzc/2.png'>

You can check the installation by running python and importing distorm3.  If you don't see any errors, distorm3 was installed correctly.<br>
<br>
<img src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVLIgeQNEyI/AAAAAAAAAxw/cND7_6bLvpE/3.png'>


<h4>Installing Yara-Python 1.4a</h4>

Download the appropriate <a href='http://code.google.com/p/yara-project/downloads/list'>yara-python-1.4a.win32-py2.X.exe</a> Windows installer.  In this guide we will use yara-python-1.4a.win32-py2.6.exe.  Double click the installer and click Next.<br>
<br>
<img width='400' height='280' src='https://lh4.googleusercontent.com/_55uSCYxbQ8M/TVLjQzWui_I/AAAAAAAAAzE/PyKLXZyKoi0/1.png'>

The installer should pick up your Python installation.  If you have more than version of Python installed, choose the installation you will be using for Volatility.<br>
<br>
<img width='400' height='280' src='https://lh4.googleusercontent.com/_55uSCYxbQ8M/TVLjRDXVnrI/AAAAAAAAAzI/cbTUKkhzpU0/2.png'>

Accept all defaults, hitting Next until complete.  As long as there are no errors shown installation should be successful.  You an always verify by running Python and typing "import yara"<br>
<br>
<h3>Installing TortoiseSVN</h3>

In order to get the source code for Volatility 2.0 from the repository, you will need a Subversion (SVN) client.  You can download the client from <a href='http://tortoisesvn.net/downloads.html'>http://tortoisesvn.net/downloads.html</a>.  Make sure to choose the correct installer:<br>
<br>
<img src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVLoO5rfotI/AAAAAAAAAzs/fS0zwywCsjA/1.jpg'>

Double click the installer and keep hitting next.  Accept all defaults and accept the user agreement.  Hit "Finish" when the installation completes.<br>
<br>
<img width='400' height='280' src='https://lh3.googleusercontent.com/_55uSCYxbQ8M/TVLm-hJqKlI/AAAAAAAAAzc/ttg-EBS_rfE/3.png'>

You will be asked to restart your computer after TortoiseSVN is installed.<br>
<br>
<img src='https://lh3.googleusercontent.com/_55uSCYxbQ8M/TVLpI0rVfWI/AAAAAAAAA0I/4ofIcaewvbU/11.png'>

After restarting, you can verify that TortoiseSVN is installed correctly by right-clicking on the Desktop.  If it is installed, you will see it in the menu:<br>
<br>
<img src='https://lh6.googleusercontent.com/_55uSCYxbQ8M/TVLqIEwzuoI/AAAAAAAAA0M/zFjmO8OO5s8/12.jpg'>




<h3>Installing Volatility 2.0 from SVN</h3>

Once you have a Subversion client installed, you can download the latest source code for Volatility 2.0 from the code repository.  This guide will use TortoiseSVN.  First create a folder where you want to keep the Volatility source code.  For this guide we will create a folder "C:\Volatility 2.0".  Go inside this folder and right-click, bringing up the menu options for TortoiseSVN.  Choose "SVN Checkout":<br>
<br>
<img src='https://lh6.googleusercontent.com/_55uSCYxbQ8M/TVLqIEwzuoI/AAAAAAAAA0M/zFjmO8OO5s8/12.jpg'>


Type the following url for the repository:<br>
<pre><code>http://volatility.googlecode.com/svn/trunk<br>
</code></pre>

<img src='https://lh5.googleusercontent.com/_55uSCYxbQ8M/TVMIuwteV3I/AAAAAAAAA0Y/cG43UU5Zep0/13.jpg'>

All other defaults should be fine, click OK.  When the repository is finished downloading click OK to close out.<br>
<br>
<img src='https://lh3.googleusercontent.com/_55uSCYxbQ8M/TVMIvBR76bI/AAAAAAAAA0c/_la0-VkUXIQ/14.png'>

You should then see all the Volatility source code in the folder.<br>
<br>
<img width='400' height='280' src='https://lh4.googleusercontent.com/_55uSCYxbQ8M/TVMIvRHz-4I/AAAAAAAAA0g/Zo69O0MGm_c/15.png'>

To use Volatility, open a command line and navigate to the Volatility source directory.  In this case:<br>
<br>
<pre><code>cd "c:\Volatility 2.0"<br>
</code></pre>

Then type:<br>
<br>
<pre><code>python vol.py -h<br>
</code></pre>



You should see a long list of output that includes all of the plugins that are available.  For more information on how to use Volatility check out BasicUsage and CommandReference.<br>
<br>
<br>
<br>
<br>
<h2>Linux Installation</h2>

This covers how to install Volatility 2.0 on Linux<br>
<br>
<h3>Installing SVN and Basic Dependencies</h3>

Luckily installation is a bit easier for Linux.  You will need to install Subversion and libpcre in addition to the dependencies listed above.  These should be available in your distribution's repository.  For example on Ubuntu (as root):<br>
<br>
<pre><code># apt-get install subversion pcregrep libpcre++-dev python-dev -y <br>
</code></pre>

For Fedora/Redhat you can use yum to install the appropriate packages.<br>
<br>
<br>
<h3>Linux: Installing Pycrypto</h3>

You have to install PyCrypto, since it is a requirement for core code. You can download the latest source from <a href='http://gitweb.pycrypto.org/?p=crypto/pycrypto-2.0.x.git;a=summary'>the pycrypto website</a> or you can find it in your Linux distribution repository.  The following commands will install this library from source on Ubuntu (you must be root to install):<br>
<br>
<pre><code>$ wget http://gitweb.pycrypto.org/\?p=crypto/pycrypto-2.0.x.git\;a=snapshot\;h=9e9641d0a9b88f09683b5f26d3b99c4a2e148da5\;sf=tgz -O pycrypto.tgz<br>
<br>
# tar -xzvf pycrypto.tgz<br>
# cd pycrypto-2.0.x/<br>
# python setup.py build<br>
# python setup.py build install<br>
</code></pre>

<h3>Linux: Installing Distorm3</h3>

For some of the malware plugins and the volshell plugin, you will need Distorm3.  The following commands will install Distorm3 from source (you must be root to install):<br>
<br>
<pre><code># wget http://distorm.googlecode.com/files/distorm3-1.0.zip<br>
# unzip distorm3-1.0.zip<br>
# cd distorm3-1.0<br>
# python setup.py build<br>
# python setup.py build install<br>
</code></pre>

<h3>Linux: Installing Yara 1.4 and Yara-Python 1.4a</h3>

For some of the malware plugins you will need to install Yara.  The following commands will install Yara and Yara-python from source (you must be root to install):<br>
<br>
For Yara:<br>
<br>
<pre><code># wget http://yara-project.googlecode.com/files/yara-1.4.tar.gz<br>
# tar -xvzf yara-1.4.tar.gz<br>
# cd yara-1.4<br>
# ./configure<br>
# make<br>
# make install<br>
</code></pre>

For Yara-python<br>
<br>
<pre><code># wget http://yara-project.googlecode.com/files/yara-python-1.4a.tar.gz<br>
# tar -xvzf yara-python-1.4a.tar.gz<br>
# cd yara-python-1.4a<br>
# python setup.py build<br>
# python setup.py build install<br>
</code></pre>

If you are on Ubuntu you will need to also run the following commands:<br>
<br>
<pre><code># echo "/usr/local/lib" &gt;&gt; /etc/ld.so.conf<br>
# ldconfig<br>
</code></pre>


<h3>Linux: Installing Volatility 2.0 from SVN</h3>

All you need to do to get download the Volatility 2.0 source code is run the following command:<br>
<br>
<pre><code>$ svn checkout http://volatility.googlecode.com/svn/trunk Volatility<br>
</code></pre>

All code will be located in Volatility<br>
<br>
To update your repository later you can run the following command from inside the trunk directory:<br>
<br>
<pre><code>$ svn update<br>
</code></pre>

<h3>Linux: Installing the Malware Plugins</h3>

Change into your Volatility/volatility/plugins directory and run the following command:<br>
<br>
<pre><code>$ wget http://malwarecookbook.googlecode.com/svn/trunk/malware.py<br>
</code></pre>


Go into your Volatility directory and type<br>
<br>
<pre><code>$ python vol.py -h<br>
</code></pre>

To help automate this, you can run the new <a href='https://github.com/gleeda/misc-scripts/raw/master/get_plugins_2.0.bsh'>get_plugins script</a> (only tested on Ubuntu and Mac OSX with Macports installed).<br>
<br>
<br>
You should see a long list of output that includes all of the plugins that are available.  For more information on how to use Volatility check out BasicUsage and CommandReference.