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
# Load optional gems
# If gruff gem is installed, the graphs will be shown with gruff. If not, the graph will be shown in command line
gruffinstalled = true
if Gem.available?('gruff')
    # Gruff needs also from libraby "rmagick". Install libmagick++-dev package for Ubuntu 11.10 and later
    require 'gruff'
else
    gruffinstalled = false
end

$executablepath = File.expand_path File.dirname(__FILE__)

# TODO: Permitir diferentes formatos de ficheros de entrada, por ejemplo usr:pwd, o usr|pwd o usr pwd, etc y añadir por tanto
#       la salida de estadísticas de dominios filtrados (gmail.com, hotmail.com, paises de los dominios, etc...)
# TODO: Añadir modulo para guardar estadísticas en un sqlite (debe preguntar pais o lenguaje del dump, perfil del dump [clasificación de los usuarios, clasificación del dump; tienda on line, web privada, acceso privado de admins, etc...])
# TODO: Añadir modulo para contar las repeticiones de letras y números
# TODO: Añadir modulo para contar las password que son fechas con diferentes formatos
# TODO: Añadir modulo para contar el nº de password que contienen una palabra o Regexp
# TODO: Añadir modulo para contar las contraseñas que contienen un listado de ciudades de un fichero
# TODO: Añadir modulo para contar las contraseñas que contienen el nombre de usuario
# TODO: Añadir opcion vervose para mostrar porcentaje de progreso con nivel 1 y password que analiza con nivel 2
# TODO: Añadir modulo para dar una puntuación de 1 a 10 la "salud" de la base de datos de contraseñas

#====================

def showBanner
  bannerf = File.open("#{$executablepath}/banner.txt","r")
  while (line = bannerf.gets)
    puts line
  end  
end

#====================

def parseOptions
    opts = {:pwdfile => nil, :ntop => 10, :charstats => true, :passwdstats => true, :regexp => '^.*(passwd|pwd|password).*$',:pwdlenstats => true}
    parser = OptionParser.new do |opt|
        opt.banner = "Usage: #{__FILE__} [options] -f <password-file>"
        opt.separator ""
        opt.separator "Specific options: "

        opt.on("-f PWDFILENAME","--pwd-file PWDFILENAME","File with one password per line (required)") do |pwdfile|
            opts[:pwdfile] = pwdfile
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
        raise OptionParser::MissingArgument if opts[:pwdfile].nil?
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
    !(Regexp.new(regexp) =~ pwd).nil?
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

#====================================
#====== MAIN ========================
#====================================

histogram = nil
maxlen = 0
minlen = 0
avglen = 0
npwd = 0
lenhist = Array.new(40) {0}
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
pwd_counter = {}
pwd_hist_ntop = {}
contains_regexp_pwd = []
i = 1

# Obtenemos las opciones de la linea de comandos
options = parseOptions

if (!File.exists?(options[:pwdfile]))
  puts "Error: No existe el fichero que has especificado"
  exit
end

f = File.open(options[:pwdfile],"r")

f.each_line{|pwd|
  pwd.strip!
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
    contains_regexp_pwd << pwd
  end
  
  lenhist[pwd.size] += 1
  
  # Save count of user passwords
  if pwd_counter.keys.include?(pwd)
      pwd_counter[pwd] += 1
  else
      pwd_counter[pwd] = 1
  end
}

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
contains_regexp_pwd.each{|matched_pwd|
    puts "-- #{matched_pwd}"
}
puts "------------------------ "
puts "==========="

if gruffinstalled
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

    strength_histogram.write("#{options[:pwdfile]}-password-strength.png")
end

puts "============"
puts "= TAMANNOS ="
size = 0

lenhist.each{|s|
  size += 1
  if s.to_f > 0.0
    lenhist_nonzero[size.to_s] = (s.to_f*100/npwd).round(2)
    puts "#{size}:\t#{s} (#{(s.to_f*100/npwd).round(2)} %)"
  end
}

if gruffinstalled
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
    len_histogram.write("#{options[:pwdfile]}-password-length.png")
end
puts "============"


# FMT (22/11/2012)
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

if gruffinstalled
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
    top_histogram.write("#{options[:pwdfile]}-password-top.png")
end
puts "===================="

