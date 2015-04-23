
require 'test_helper'

class CryptoTest < ActionView::TestCase

    def setup
        # replace this with your encryption key
        @encryption_key = "asasasasasasasasasaassa"
    end

    def test_encrypt_decrypt_reversibility
        sample_plain_text = "Sample Text with special characters like (,),*,&,^,%"
        cipher_text = CCAvenue::Crypto.encrypt(sample_plain_text, @encryption_key)
        assert_not_equal sample_plain_text,cipher_text
        decrypted_text = CCAvenue::Crypto.decrypt(cipher_text, @encryption_key)
        assert_equal sample_plain_text,decrypted_text
    end

    def test_encrypt_decrypt_reversibility_with_merchant_data
        command            = "initiateTransaction"
        access_code        = "asasasasasasasas"  # replace with Access code provided by payment gateway
        submit_url         = "https://secure.ccavenue.com/transaction/transaction.do"
        merchant_id        = "wewewe"            # replace with Merchant_id provided by payment gateway
        order_id           = "12345"             # your unique order id 
        currency           = "INR"
        amount             = 1000.00
        redirect_url       = "http://yoursite.com/payment_redirect_url"
        cancel_url         = "http://yoursite.com/cancel_redirect_url"
        integration_type   = "iframe_normal"
        language           = "EN"
        billing_name       = "George Washingtom"
        billing_address    = "Shastri Nagar"
        billing_city       = "Delhi"
        billing_state      = "Delhi"
        billing_zip        = "12345"
        billing_country    = "India"
        billing_tel        = "9999999999"
        billing_email      = "sample32@gmail.com"
        billing_notes      = "Sample notes"
        merchant_param1    = "Sample Merchant params"
        merchant_data      = "merchant_id=#{merchant_id}&order_id=#{order_id}&amount=#{amount}&currency=#{currency}&redirect_url=#{redirect_url}&cancel_url=#{cancel_url}&language=#{language}&billing_name=#{billing_name}&billing_address=#{billing_address}&billing_city=#{billing_city}&billing_state=#{billing_state}&billing_zip=#{billing_zip}&billing_country=#{billing_country}&billing_tel=#{billing_tel}&billing_email=#{billing_email}&billing_notes=#{billing_notes}&merchant_param1=#{merchant_param1}&integration_type=#{integration_type}"
        cipher_text        = CCAvenue::Crypto.encrypt(merchant_data, @encryption_key)
        assert_not_equal merchant_data,cipher_text
        decrypted_text     = CCAvenue::Crypto.decrypt(cipher_text, @encryption_key)
        assert_equal merchant_data, decrypted_text
    end
end
