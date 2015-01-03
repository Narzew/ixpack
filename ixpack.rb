#** Ix Pack Secure Archive Packer & Crypter by Narzew
#** v 1.00
#** 18.10.2013

require 'zlib'

$master_key = rand(0xFFFFFF)
$master_key2 = "msv739fc1"

module NRGSS
	def self.location_table(locations_ary)
		result = []
		locations_ary.each{|location|
		Dir.foreach(location){|x|
			if x != '.'
				if x != '..'
					result << "#{location}/#{x}"
				end
			end
			}
		}
		return result
	end
end

module IxPack
	def self.transform_key(x)
		r = 0
		c = 1
		x.to_s.crypt("#{$master_key2}-#{$master_key}").each_byte{|x|
			r += x.to_i*(c*256)
			c += 1
		}
		r = r%0xFFFFFF
		return r
	end
	def self.encrypt_stream(x,k)
		k = IxPack.transform_key(k)
		srand(IxPack.transform_key(k))
		s = ""
		x.each_byte{|b|
			s << ((b+rand(999999)+7+k-transform_key("#{$master_key}+#{$master_key2}"))%256).chr
			k=(k*6+4)%0xFFFFFF
			srand(k)	
		}
		return s
	end
	def self.decrypt_stream(x,k)
		k = IxPack.transform_key(k)
		srand(IxPack.transform_key(k))
		s = ""
		x.each_byte{|b|
			s << ((b-k-7-rand(999999)+transform_key("#{$master_key}+#{$master_key2}"))%256).chr
			k=(k*6+4)%0xFFFFFF
			srand(k)
		}
		return s
	end
	def self.pack(files,arch)
		$result = ["IXP1",$master_key,[]]
		files.each{|x|
			name = x.crypt("#{$master_key}.#{$master_key2}")
			name2 = x.crypt("sfn9as8fh#{$master_key2},#{$master_key}$")
			data = lambda{|x|File.open(x,'rb'){|f|return Zlib::Deflate.deflate(f.read,9)}}.call(x)
			data = IxPack.encrypt_stream(data,name)
			$result[2] << [name2,data]
		}
		$result = Marshal.dump($result)
		File.open(arch,'wb'){|w|w.write($result)}
	end
	def self.decrypt_file(filename, arch, key="")
		if key != nil && key != ""
			$master_key2 = key
		end
		data = lambda{|x|File.open(x,'rb'){|f|return f.read}}.call(arch)
		data = Marshal.load(data)
		$master_key = data[1]
		data = data[2]
		name = filename.crypt("sfn9as8fh#{$master_key2},#{$master_key}$")
		data.each{|x|
			if x[0] == name
				data = x[1]
				break
			end
		}
		key = filename.crypt("#{$master_key}.#{$master_key2}")
		data = IxPack.decrypt_stream(data,key)
		data = Zlib::Inflate.inflate(data)
		File.open(filename,'wb'){|w|w.write(data)}
	end
end
		
		
begin
	print "IxPack v 1.00 by Narzew\n"
	if ARGV.size == 0
		print "Invalid Args!\nType IxPack.rb h for help\n"
	elsif ARGV[0] == "e"
		$files = NRGSS.location_table([ARGV[1]])
		if ARGV[3] != nil && ARGV[3] != ""
			$master_key2 = ARGV[3]
		end
		IxPack.pack($files,ARGV[2])
	elsif ARGV[0] == "d"
		IxPack.decrypt_file(ARGV[1],ARGV[2],ARGV[3])
	elsif ARGV[0] == "h"
		print "IxPack.rb e folder file key - encrypt\nIxPack.rb d filename file key - decrypt\nIxPack.rb h - show help\n"
	end
end
