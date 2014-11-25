FAP
===

Fast Analyzer for your Passwords 
--------------------------------

Summary
-------
This tool alows you to statisticaly analyze the strength of a dump of passwords.

As a result of the analysis you'll get the histograms of the passwords length and the strength of them.
You'll also have the posibility to see the percentage of passwords that match some regular expresion.

Bug reports to Felipe Molina: felmoltor@gmail.com or https://www.twitter.com/felmoltor.

Install
-------

$ git clone https://github.com/felmoltor/FAP
$ sudo gem install bundler
$ bundler install

Usage
-----
``` 
Usage: ./fap.rb [options] -f <dump-file>

Specific options: 
    -f, --pwd-file DUMPFILE          File with one password per line (required)
    -t, --top-passwd [NUMBER]        Size of the list with the most repeated passwords
    -F, --format [FORMAT]            The input file can be one of the following format (UFSP,P,U). Default is "P"
        --separator [SEPARATOR]      If the file type is UFSP, you can specify here the Field Separator character. Default is ":"
    -r, --[no-]regsearch             Search regexp withing password list (default is False)
    -E, --regexp [REGEXP]            Search a regular expression within the passwords (default is "^.*(passwd|pwd|password).*$")
    -h, --help                       Print help and usage information
```

