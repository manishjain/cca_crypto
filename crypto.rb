#
# The module contains methods required for securely communicating with the payment gateway.
#
# Author::    Manish Jain  (mailto:oss@elitmus.com)
# Copyright:: Copyright (c) 2014 eLitmus.com, Bangalore (India)
# Version::   0.1.0
# License::   Distributed under GPLV3
#
# To use this module in your Ruby-on-Rails application, copy this file into <tt>{RAILS_ROOT}/app/config/initializers/</tt>
#
# There are two methods, [encrypt] and [decrypt]
# * The *encrypt* method:: This allows one to encrypt the message to be posted from
#     merchant site to the payment gateway. 
# * The *decrypt* method:: This allows one to decrypt the message received from the payment gateway
#
#
# The syntax to call the encrypt method is:
#  <tt>encrypted_data   = CCAvenue::Crypto.encrypt(merchant_data,encryption_key)</tt>
#
# The syntax to call the decrypt method is:
#  <tt>decrypted_data   = CCAvenue::Crypto.decrypt(encResponse,encryption_key)</tt>
#
# Since this is going to be a cross-site request, you need to exclude the relevent actions of your controller from the *protect_from_forgery* filter.
# For example,
#   <tt>protect_from_forgery :except => [:process_payment_iframe]</tt>
#
require "digest/md5"
require 'openssl'

module CCAvenue
    class Crypto
        INIT_VECTOR = (0..15).to_a.pack("C*")

        # *encrypt* : This method is used to encrypt merchant data and customer information in order to pass it to payment gateway(ccavenue)
        #
        # *Input Parameters:*
        # <tt>plain_text</tt> : This consiste of the query string that needs to be appended to <tt>submit_url</tt>. The format is like this
        #   Note that newlines have been added for improved readability. The actul <tt>plain_text</tt> should be one long string
        #
        #        merchant_id=somevalue&
        #        order_id=somevalue&
        #        amount=somevalue&
        #        currency=somevalue&
        #        redirect_url=somevalue&
        #        cancel_url=somevalue&
        #        language=somevalue&
        #        billing_name=somevalue&
        #        billing_address=somevalue&
        #        billing_city=somevalue&
        #        billing_state=somevalue&
        #        billing_zip=somevalue&
        #        billing_country=somevalue&
        #        billing_tel=somevalue&
        #        billing_email=somevalue&
        #        billing_notes=somevalue&
        #        delivery_name=somevalue&
        #        delivery_address=somevalue&
        #        delivery_city=somevalue&
        #        delivery_state=somevalue&
        #        delivery_zip=somevalue&
        #        delivery_country=somevalue&
        #        delivery_tel=somevalue&
        #        merchant_param1=somevalue&
        #        merchant_param2=somevalue&
        #        merchant_param3=somevalue&
        #        merchant_param4=somevalue&
        #        integration_type=somevalue
        #
        #  <tt>key</tt> : This is the *Encryption Key* provided by the payment gateway. 
        #
        # *Output Parameters:*
        #  <tt>encrypted_text</tt> : This is the encrypted data that can be passed on to the payment gateway. 
        #  
        # The method returns <tt>encrypted_data</tt> which is pased as one of the parameter in source url for iframe, like this
        # "#{submit_url}?command=#{command}&encRequest=#{encrypted_data}&access_code=#{access_code}"

        def self.encrypt(plain_text, key)
            secret_key =  [Digest::MD5.hexdigest(key)].pack("H*") 
            cipher = OpenSSL::Cipher::Cipher.new('aes-128-cbc')
            cipher.encrypt
            cipher.key = secret_key
            cipher.iv  = INIT_VECTOR
            encrypted_text = cipher.update(plain_text) + cipher.final
            return (encrypted_text.unpack("H*")).first
        end


        # *decrypt* : This method is used to decrypt the <tt>cipher_text</tt> (or encrypted data) received from the payment gateway (ccavenue) 
        # after a transaction is complete and action returns to merchant website.
        #
        # *Input Parameters:*
        #  <tt>cipher_text : </tt> This is the encrypted data received from the payment gateway.
        #
        #  <tt>key</tt> : This is the *Encryption Key* provided by the payment gateway. 
        #
        # *Output Parameters:*
        #  <tt>decrypted_text</tt> : Decrypted text will contain the following string:
        #
        #   Note that newlines have been added for improved readability. The actul <tt>decrypted_text</tt> is one long string
        #
        #    order_id=somevalue&
        #    tracking_id=somevalue&
        #    bank_ref_no=somevalue&
        #    order_status=somevalue&
        #    failure_message=somevalue&
        #    payment_mode=somevalue&
        #    card_name=somevalue&
        #    status_code=somevalue&
        #    status_message=somevalue&
        #    currency=INR&
        #    amount=1.0&
        #    billing_name=somevalue&
        #    billing_address=somevalue&
        #    billing_city=somevalue&
        #    billing_state=somevalue&
        #    billing_zip=somevalue&
        #    billing_country=India&
        #    billing_tel=somevalue&
        #    billing_email=somevalue&
        #    delivery_name=somevalue&
        #    delivery_address=somevalue&
        #    delivery_city=somevalue&
        #    delivery_state=somevalue&
        #    delivery_zip=somevalue&
        #    delivery_country=somevalue&
        #    delivery_tel=somevalue&
        #    merchant_param1=somevalue&
        #    merchant_param2=somevalue&
        #    merchant_param3=somevalue&
        #    merchant_param4=somevalue&
        #    merchant_param5=somevalue
        #
    
        def self.decrypt(cipher_text, key)
            secret_key =  [Digest::MD5.hexdigest(key)].pack("H*")
            encrypted_text = [cipher_text].pack("H*")
            decipher = OpenSSL::Cipher::Cipher.new('aes-128-cbc')
            decipher.decrypt
            decipher.key = secret_key
            decipher.iv  = INIT_VECTOR
            decrypted_text = (decipher.update(encrypted_text) + decipher.final).gsub(/\0+$/, '')
            return decrypted_text
        end
    end
end