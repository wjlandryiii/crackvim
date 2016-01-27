crackvim
========

cracks vim encrypted text files. only supports default encryption level (zip).


Help screen
-----------

    $ ./crackvim
    crackvim: [options] [filename]
    
    Options:
    	-b nbytes (default: 128)
    	-d dict_file
    	-p start_password (default: empty string)
    	-C charset (default: 0)
    	-l max_passwd_len (default: 6)
    	-c crib
    
    $


Brute Force Example
-------------------

    $ ./crackvim test.txt
    loaded test.txt: 40 bytes
    searching for ascii text files
    using brute force
    max password length: 6
    charset: 0
    
    Possible password: 'lenin'
    Plaintext: meet at the park on tuesday
    
    $


Dictionary Example
------------------

    $ ./crackvim -d /usr/share/dict/words dict_test.txt
    loaded dict_test.txt: 54 bytes
    searching for ascii text files
    using dictionary file: /usr/share/dict/words
    
    Possible password: 'unobjectionableness'
    Plaintext: sell all shares before the board meeting.
    
    $
