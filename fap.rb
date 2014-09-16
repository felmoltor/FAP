#!/usr/bin/ruby

""" 
Copyright (C) 2012  Felipe Molina (@felmoltor)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

require 'rubygems'
require 'optparse'
require 'gruff'
require 'facets'

$executablepath = File.expand_path File.dirname(__FILE__)

# TODO: Añadir modulo para guardar estadísticas en un sqlite (debe preguntar pais o lenguaje del dump, perfil del dump [clasificación de los usuarios, clasificación del dump; tienda on line, web privada, acceso privado de admins, etc...])
# TODO: Añadir modulo para contar las repeticiones de letras y números
# TODO: Añadir modulo para contar las password que son fechas con diferentes formatos
# TODO: Añadir modulo para contar las contraseñas que contienen un listado de ciudades de un fichero
# TODO: Añadir modulo para contar las contraseñas que contienen el nombre de usuario
# TODO: Añadir modulo para dar una puntuación de 1 a 10 la "salud" de la base de datos de contraseñas

# Globals (bad, very bad)
$percentagestep=5

#====================

def showBanner
  bannerf = File.open("#{$executablepath}/banner.txt","r")
  while (line = bannerf.gets)
    puts line
  end  
end


#====================

def calculateETA(currentrow,totalrows,startepoch)
  runseconds=Time.now.to_i-startepoch
  etaseconds = (totalrows-currentrow).to_f/(currentrow.to_f/runseconds.to_f)
  return etaseconds
end

#====================

def detectDumpType(dumpfile)
  seemslike = "P"
  nlinesprobe = 50
  # Analizamos los X primeros records del dump
  cont=0
  f = File.open(dumpfile,"r")
  f.each{|dumpline|
    if cont==nlinesprobe
      break
    end
    cont+=1
    # Detect kind of dump (U,P,UFSP, other?)
    # Seems like email FS and password?
    memailpass = /^.+\@.+\..{2,}:.*$/.match(dumpline)
    memailpass = /^.+\@.+\..{2,}\|.*$/.match(dumpline)
    memailpass = /^.+\@.+\..{2,}\s+.*$/.match(dumpline)
    memailpass = /^.+:.*$/.match(dumpline)
    memailpass = /^.+\|.*$/.match(dumpline)
    memailpass = /^.+\s+.*$/.match(dumpline)
    # Seems like email and nothing more?
    
    # Seems like strings?
    
  }
  f.close
  return seemslike
end

#====================

def parseOptions
    opts = {:dumpfile => nil, :ntop => 10, :format => "P", :fieldseparator => ":", :charstats => true, :passwdstats => true, :regexp => '^.*(passwd|pwd|password).*$',:pwdlenstats => true}
    parser = OptionParser.new do |opt|
        opt.banner = "Usage: #{__FILE__} [options] -f <dump-file>"
        opt.separator ""
        opt.separator "Specific options: "

        opt.on("-f DUMPFILE","--pwd-file DUMPFILE","File with one password per line (required)") do |dumpfile|
            opts[:dumpfile] = dumpfile
        end
        opt.on('-t [NUMBER]','--top-passwd [NUMBER]',Integer, 'Size of the list with the most repeated passwords') do |ntop|
            opts[:ntop] = ntop
        end
        opt.on('-c','--no-char-stats', 'Disable analysis for character frecuency') do
            opts[:charstats] = false
        end
        opt.on('-p','--no-passwd-stats', 'Disable analysis for passwords frecuency') do
            opts[:passwdstats] = false
        end
        opt.on('-l','--no-len-stats','Disable analysis for length of passwords') do
            opts[:pwdlenstats] = false
        end
        opt.on('-F [FORMAT]','--format [FORMAT]','The input file can be one of the following format (UFSP,P,U). Default is "P"') do |format|
            if format.strip == "U" or format.strip == "P" or format.strip == "UFSP"
              opts[:format] = format
            else
              opts[:format] = "P"
            end
        end
        opt.on('--separator [FIELD SEPARATOR]','If the file type is UFSP, you can specify here the Field Separator character. Default is ":"') do |fs|
            if fs.size != 1
              opts[:fieldseparator] = ":"
            else
              opts[:fieldseparator] = fs
            end
        end
        opt.on('-E [REGEXP]','--regexp [REGEXP]','Search the specified regular expression within the password file (default is "^.*(passwd|pwd|password).*$")') do |regexp|
            opts[:regexp] = regexp
        end
        opt.on("-h","--help", "Print help and usage information") do
            puts parser
            exit
        end
    end # del parse do

    begin
        # Show FAP banner
        # showBanner
        parser.parse($*)
        # Controlamos las opciones obligatorias
        raise OptionParser::MissingArgument if opts[:dumpfile].nil?
    rescue OptionParser::ParseError
        puts "Error with the options provided"
        puts parser
        exit
    end
    opts
end

#====================

# Regexp: Check if match with the regular expression specified in the arguments
def containsRegexp(pwd,regexp)
  r = Regexp.compile(regexp)
  !(r.match(pwd)).nil?
end
#===============

# Complex: letters, numbers, uper case and lower case, special chars presents
def isComplex(pwd)
  !(pwd.index(/[a-z]+/).nil? or pwd.index(/[A-Z]+/).nil? or pwd.index(/[0-9]+/).nil? or pwd.index(/[^a-zA-Z0-9]+/).nil?)
end
#==============

# letters, numbers, upper case and lower case
def isUpperLowerNums(pwd)
  !(pwd.index(/[a-z]+/).nil? or pwd.index(/[A-Z]+/).nil? or pwd.index(/[0-9]+/).nil?) and (pwd.index(/^a-zA-Z0-9/).nil?)
end

#=============
# letters, upper case and lower case
def isUpperLower(pwd)
  !(pwd.index(/[a-z]+/).nil? or pwd.index(/[A-Z]+/).nil?) and (pwd.index(/^a-zA-Z0-9/).nil? and pwd.index(/[0-9]+/).nil?)
end
#=============
# lower case only letters and numbers
def isLowerCaseNums(pwd)
  !(pwd.index(/[a-z]+/).nil? or pwd.index(/[0-9]+/).nil?) and (pwd.index(/^a-zA-Z0-9/).nil? and pwd.index(/[A-Z]+/).nil?)
end
#============
# upper case only letters and numbers
def isUpperCaseNums(pwd)
  !(pwd.index(/[A-Z]+/).nil? or pwd.index(/[0-9]+/).nil?) and (pwd.index(/^a-zA-Z0-9/).nil? and pwd.index(/[a-z]+/).nil?)
end
#===========
# lower case letters only
def isLowerCaseOnly(pwd)
  !(pwd.index(/[a-z]+/).nil?) and (pwd.index(/^a-zA-Z0-9/).nil? and pwd.index(/[0-9]+/).nil? and pwd.index(/[A-Z]+/).nil?)
end
#===========
# upper case letters only
def isUpperCaseOnly(pwd)
  !(pwd.index(/[A-Z]+/).nil?) and (pwd.index(/^a-zA-Z0-9/).nil? and pwd.index(/[0-9]+/).nil? and pwd.index(/[a-z]+/).nil?)
end

#============

def isOnlyNumbers(pwd)
  !(pwd.index(/[0-9]+/).nil?) and (pwd.index(/^a-zA-Z0-9/).nil? and pwd.index(/[A-Z]+/).nil? and pwd.index(/[a-z]+/).nil?)
end

#============

def getCharRepetitions(pwd)
  # Every char
end

#==================
#====== MAIN ======
#==================

histogram = nil
maxlen = 0
minlen = 0
avglen = 0
npwd = 0
lenhist = {}
lengths = []
lenhist_nonzero = {}
containsregexp = 0
complex = 0
upperandlownum = 0
upperandlow = 0
lowcasenum = 0
upcasenum = 0
lowercaseonly = 0
uppercaseonly = 0
onlynumber = 0
other = 0
ntop = 10
len_histogram = nil
strength_histogram = nil
domain_counter = {}
pwd_counter = {}
pwd_hist_ntop = {}
domain_hist_ntop = {}
contains_regexp_pwd = {}
dumpfilename = ""
ndumpline=0
ndumptotal=0
lastshown=0
startepoch = Time.now.to_i

# Obtenemos las opciones de la linea de comandos
options = parseOptions

if (!File.exists?(options[:dumpfile]))
  puts "Error: No existe el fichero que has especificado"
  exit
else
  extn = File.extname(options[:dumpfile])
  dumpfilename = File.basename(options[:dumpfile],extn)
end

# Get number of lines of the dump
ndumptotal=%x( wc -l #{options[:dumpfile]} ).to_i

if options[:format] == "UFSP"
  puts "Analyzing a file with user, passwords and separator '#{options[:fieldseparator]}'"
elsif options[:format] == "U"
  puts "Analyzing a file with only usernames"  
else
  puts "Analyzing a file with only passwords"
end

f = File.open(options[:dumpfile],"r")
puts "Loading the whole dump file. Be patient..."
dumplines = f.readlines()
f.seek(0)

# Read all lines to an array
dumpusers = []
dumpnames = []
dumppass = []
dumpdomains = []
puts "Spliting the dump information..."
dumplines.each{|dline|
  begin
    dline.strip!
    if options[:format] == "UFSP"
      dsplit = dline.split(options[:fieldseparator])
      dumpusers << dsplit[0]
      if !dsplit[1].nil? and dsplit[1].size > 0
        dumppass << dsplit[1]
      else
        dumppass << "<empty>"
      end
      mailmatch = /^(.*)\@(.*\..{2,}$)/.match(dsplit[0])
      if !mailmatch.nil? 
        if !mailmatch[1].nil?
          dumpnames << mailmatch[1]
        end
        if !mailmatch[2].nil?
          dumpdomains << mailmatch[2]          
        end
      end
    elsif options[:format] == "U"
      dumpusers << dline
      mailmatch = /^(.*)\@(.*\..{2,}$)/.match(dline)
      if !mailmatch.nil?
        if !mailmatch[1].nil?
          dumpnames << mailmatch[1]
        end
        if !mailmatch[2].nil?
          dumpdomains << mailmatch[2]          
        end
      end
    else # Is a password file
      if dline.strip.size > 0
        dumppass << dline
      else
        dumppass << "<empty>"
      end
    end
  rescue Exception => e
    $stderr.puts "Error with line #{dline} (#{e.message})"
  end
} 
# Histograma de passwords usando librería facets
puts "Analycing the password frecuency..."
pwd_counter = dumppass.frequency
puts "Analycing the domains frecuency..."
domain_counter = dumpdomains.frequency

# 
puts "Analycing passwords complexity..."
dumppass.each{|pwd|
  if !pwd.nil? and pwd.size > 0
    npwd += 1   
    if (isComplex(pwd))
      complex +=1
    elsif (isUpperLowerNums(pwd))
      upperandlownum += 1
    elsif (isUpperLower(pwd))
      upperandlow += 1
    elsif (isLowerCaseNums(pwd))
      lowcasenum += 1
    elsif (isUpperCaseNums(pwd))
      upcasenum += 1
    elsif (isLowerCaseOnly(pwd))
      lowercaseonly += 1
    elsif (isUpperCaseOnly(pwd))
      uppercaseonly += 1
    elsif (isOnlyNumbers(pwd))
      onlynumber += 1
    else
      other += 1
    end
    
    if containsRegexp(pwd,options[:regexp])
      containsregexp += 1
      if (contains_regexp_pwd[pwd].nil?)
        contains_regexp_pwd[pwd] = 1
      else
        contains_regexp_pwd[pwd] += 1
      end
    end
    
    lengths << pwd.size
    
    ndumpline+=1
    progress = ((ndumpline.to_f/ndumptotal.to_f)*100.0).to_i
    if progress%$percentagestep == 0
      if lastshown!=progress
        time = Time.new
        etaseconds=calculateETA(ndumpline,ndumptotal,startepoch)
        enddate=Time.now.to_i+etaseconds
        speed=ndumpline/(Time.now.to_i-startepoch)
        puts " #{progress}% - Line #{ndumpline} of #{ndumptotal}\t(#{speed} pass/sec, ETA #{Time.at(enddate).strftime("%Y-%m-%d %H:%M:%S")})"
        lastshown=progress
      end
    end
  end
}

lenhist = lengths.frequency

###################
# Results section #
###################

puts "= RESULTS ="
puts "- Complex: #{complex} (#{(complex.to_f*100/npwd).round(2)} %)"
puts "- Upper and Low and numbers: #{upperandlownum} (#{(upperandlownum.to_f*100/npwd).round(2)} %)"
puts "- Upper and Low only: #{upperandlow} (#{(upperandlow.to_f*100/npwd).round(2)} %)"
puts "- Low case and numbers: #{lowcasenum} (#{(lowcasenum.to_f*100/npwd).round(2)} %)"
puts "- Upper case and numbers: #{upcasenum} (#{(upcasenum.to_f*100/npwd).round(2)} %)"
puts "- Low case only: #{lowercaseonly} (#{(lowercaseonly.to_f*100/npwd).round(2)} %)"
puts "- Upper case only: #{uppercaseonly} (#{(uppercaseonly.to_f*100/npwd).round(2)} %)"
puts "- Numbers only: #{onlynumber} (#{(onlynumber.to_f*100/npwd).round(2)} %)"
puts "- Other: #{other} (#{(other.to_f*100/npwd).round(2)} %)"
puts "------------------------ "
puts "- Contains the regexp (#{options[:regexp]}): #{containsregexp} (#{(containsregexp.to_f*100/npwd).round(2)} %): "
contains_regexp_pwd = contains_regexp_pwd.sort_by {|key, value| value}.reverse
contains_regexp_pwd.each{|matched_pwd,times|
    puts "-- #{matched_pwd}: #{times}"
}
puts "------------------------ "

i = 1
puts "==============="
puts "= Top #{options[:ntop]} domains ="
domain_hist = domain_counter.sort_by{|k,v| v}.reverse
domain_hist.each {|domain,nrepetitions|
  puts "#{i} - #{domain}: #{nrepetitions}"
  domain_hist_ntop[domain] = nrepetitions
  if i >= options[:ntop]
    break
  end
  i += 1
}
puts "==============="

puts "==========="
strength_histogram = Gruff::Pie.new
strength_histogram.title = "Password strength"
# strength_histogram.x_axis_label = "Strength"
# strength_histogram.y_axis_label = "Percentage (%)"
strength_histogram.hide_legend = false
strength_histogram.legend_font_size = 15
strength_histogram.legend_box_size = 15
# Data
strength_histogram.data("Complex",(complex.to_f*100/npwd).round(2))
strength_histogram.data("Up & Low case only",(upperandlow.to_f*100/npwd).round(2))
strength_histogram.data("Up & Low & Numbers",(upperandlownum.to_f*100/npwd).round(2))
strength_histogram.data("Low & Numbers",(lowcasenum.to_f*100/npwd).round(2))
strength_histogram.data("Up & Numbers",(upcasenum.to_f*100/npwd).round(2))
strength_histogram.data("Low case",(lowercaseonly.to_f*100/npwd).round(2))
strength_histogram.data("Up case",(uppercaseonly.to_f*100/npwd).round(2))
strength_histogram.data("Numbers",(onlynumber.to_f*100/npwd).round(2))
strength_histogram.data("Others",(other.to_f*100/npwd).round(2))

strength_histogram.write("outputs/#{dumpfilename}-password-strength.png")

puts "========="
puts "= SIZES ="
size = 0

lenhist.sort.each{|pwdlen,count|
  if pwdlen > 0
    lenhist_nonzero[pwdlen] = (count.to_f*100/npwd).round(2)
    puts "#{pwdlen}:\t#{count} (#{(count.to_f*100/npwd).round(2)}%)"
  end
}

x_labels = {}
labelindex = 0

len_histogram = Gruff::Bar.new
len_histogram.title = "Password Lengths"
len_histogram.x_axis_label = "Password Length"
len_histogram.y_axis_label = "Percentage (%)"
len_histogram.sort = false
len_histogram.hide_legend = true
# Data
len_histogram.data("Password Length", lenhist_nonzero.values)
lenhist_nonzero.each {|size_key,percentage_val|
  x_labels[labelindex] = size_key.to_s
  labelindex += 1 
} 
len_histogram.labels = x_labels
len_histogram.write("outputs/#{dumpfilename}-password-length.png")
puts "========="


puts "====================="
puts "= Passwords entropy ="
puts dumppass.entropy
puts "====================="

# FMT (22/11/2012)
i = 1
puts "===================="
puts "= Top #{options[:ntop]} passwords ="
pwd_hist = pwd_counter.sort_by{|k,v| v}.reverse
pwd_hist.each {|pass,nrepetitions|
  puts "#{i} - #{pass}: #{nrepetitions}"
  pwd_hist_ntop[pass] = nrepetitions
  if i >= options[:ntop]
    break
  end
  i += 1
}

y_labels = {}
labelindex = 0

top_histogram = Gruff::SideBar.new
top_histogram.title = "Top #{options[:ntop]} Repeated Passwords"
top_histogram.y_axis_label = "Password"
top_histogram.x_axis_label = "Number of repetitions (of #{npwd})"
top_histogram.sort = false
top_histogram.hide_legend = true
# Data
top_histogram.data("Repeated Passwords", pwd_hist_ntop.values,"#FE5010")
pwd_hist_ntop.each {|pwd,nrep|
  y_labels[labelindex] = pwd.to_s
  labelindex += 1 
} 
top_histogram.labels = y_labels
top_histogram.y_axis_increment = 1
top_histogram.write("outputs/#{dumpfilename}-password-top.png")
puts "===================="

