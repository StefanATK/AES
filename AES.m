classdef AES < handle
    %AES Class
    %
    
    properties (Access = private)
        secretKey
        cipher
    end
    
    methods
        function obj = AES(secret, algorithm)
            %% AES Construct an instance of this class
            %   algorithm options are https://docs.oracle.com/javase/9/docs/specs/security/standard-names.html#messagedigest-algorithms
			%
			% MessageDigest Algorithms
			% 
			% Algorithm names that can be specified when generating an instance of MessageDigest.
			% Algorithm Name 	Description
			% MD2 	The MD2 message digest algorithm as defined in RFC 1319.
			% MD5 	The MD5 message digest algorithm as defined in RFC 1321.
			% SHA-1
			% SHA-224
			% SHA-256
			% SHA-384
			% SHA-512/224
			% SHA-512/256 	Hash algorithms defined in FIPS PUB 180-4. Secure hash algorithms - SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 - for computing a condensed representation of electronic data (message). When a message is input to a hash algorithm, the result is an output called a message digest. A message digest ranges in length from 160-512 bits, depending on the algorithm.
			%
			% SHA3-224
			% SHA3-256
			% SHA3-384
			% SHA3-512		Permutation-based hash and extendable-output functions as defined in FIPS PUB 202. An input message length can vary; the length of the output digest is fixed.
			% 
			% SHA3-224		produces a 224 bit digest.
			% SHA3-256		produces a 256 bit digest.
			% SHA3-384		produces a 384 bit digest.
			% SHA3-512		produces a 512 bit digest.
			
            import java.security.MessageDigest;
            import java.lang.String;
            import java.util.Arrays;
            import javax.crypto.Cipher;
            
            key = String(secret).getBytes("UTF-8");
            sha = MessageDigest.getInstance(algorithm);
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            obj.secretKey = javaObject('javax.crypto.spec.SecretKeySpec',key, "AES");
            obj.cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        end
        
		function encrypted = encrypt(obj, uint8ToEncrypt)
            %% ENCRYPT Summary of this method goes here
            %   Detailed explanation goes here           
            import javax.crypto.Cipher;
            
			if ~isa(uint8ToEncrypt,'uint8')
				error('MATLAB:AES:Datatype', 'Wrong data type for the Data.')
			end
            obj.cipher.init(Cipher.ENCRYPT_MODE, obj.secretKey);
            encrypted = obj.cipher.doFinal(uint8ToEncrypt);
		end
		
		function decrypted = decrypt(obj, uint8ToDecrypt)
            %DECRYPT Summary of this method goes here
            %   Detailed explanation goes here
            import javax.crypto.Cipher;
            
            obj.cipher.init(Cipher.DECRYPT_MODE, obj.secretKey);
            decrypted = typecast(obj.cipher.doFinal(uint8ToDecrypt),'uint8');
		end
		
		function encrypted = encrypt_str(obj, strToEncrypt)
            %% ENCRYPT Summary of this method goes here
            %   Detailed explanation goes here           
            import java.util.Base64;
            import java.lang.String;
            import javax.crypto.Cipher;
            
            obj.cipher.init(Cipher.ENCRYPT_MODE, obj.secretKey);
            encrypted = string(Base64.getEncoder().encodeToString(obj.cipher.doFinal(String(strToEncrypt).getBytes("UTF-8"))));
		end
		
		function decrypted = decrypt_str(obj, strToDecrypt)
			%% ENCRYPT Summary of this method goes here
            %   Detailed explanation goes here 
            %DECRYPT Summary of this method goes here
            %   Detailed explanation goes here
            import javax.crypto.Cipher;
            import java.lang.String;
            import java.util.Base64;
            
            obj.cipher.init(Cipher.DECRYPT_MODE, obj.secretKey);
            decrypted = string(String(obj.cipher.doFinal(Base64.getDecoder().decode(strToDecrypt))));
        end
		
        function encrypted = encryptStructuredData(obj, structuredData)
			%% ENCRYPT Summary of this method goes here
            %   Detailed explanation goes here 
            encrypted = obj.encrypt_str(jsonencode(structuredData));
        end
        
        function decrypted = decryptStructuredData(obj, encryptedStructuredData)
			%% ENCRYPT Summary of this method goes here
            %   Detailed explanation goes here 
            decrypted = jsondecode(obj.decrypt_str(encryptedStructuredData));
        end        
        
        function ret = chkCryptStructuredData(obj,encryptedStructuredData1, encryptedStructuredData2)
			%% ENCRYPT Summary of this method goes here
            %   Detailed explanation goes here 
			narginchk(3, 3);
			data1 = decryptStructuredData(obj, encryptedStructuredData1);
			data2 = decryptStructuredData(obj, encryptedStructuredData2);
			ret = false;
			if length(data1) == length(data2)
				ret = all(data1==data2);
			end
		end
    end
end


