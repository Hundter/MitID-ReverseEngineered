import json, os, binascii, hashlib, base64, requests, time, hmac, uuid, random
import argparse
from datetime import datetime, timezone
from Crypto.PublicKey import ECC, RSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS, pkcs1_15
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from CustomSRP import CustomSRP, BLOCK_SIZE, unpad

class Authenticator():
    def __init__(self, user_id):
        self.user_id = user_id
        
        with open("constants.json", 'rb') as constants_file:
            self.constants = json.load(constants_file)

        hex_user_id = binascii.hexlify(self.user_id.encode('utf-8')).decode('utf-8')
        if os.path.isfile(hex_user_id + "_config.json"):
            with open(hex_user_id + "_config.json") as user_config_file:
                user_config = json.load(user_config_file)
                self.auth_seed = binascii.unhexlify(user_config["authSeed"])
                self.authenticator_id = user_config["authenticatorId"]
                self.client_salt = user_config["clientSalt"]
                self.pin = user_config["pin"]
                self.ecc_key = ECC.import_key(binascii.unhexlify(user_config["eccKey"]), curve_name='secp256r1')
                self.rsa_key = RSA.import_key(binascii.unhexlify(user_config["rsaKey"]))
                self.app_instance_id = user_config["appInstanceId"]
                self.user_exists = True
        else:
            self.user_exists = False

    def __save_authenticator(self):
        user_config = {
            "userId": self.user_id,
            "authSeed": binascii.hexlify(self.auth_seed).decode('utf-8'),
            "authenticatorId": self.authenticator_id,
            "clientSalt": self.client_salt,
            "pin": self.pin,
            "eccKey": binascii.hexlify(self.ecc_key.export_key(format='PEM').encode('utf-8')).decode('utf-8'),
            "rsaKey": binascii.hexlify(self.rsa_key.export_key(format='PEM')).decode('utf-8'),
            "appInstanceId": self.app_instance_id
        }

        hex_user_id = binascii.hexlify(self.user_id.encode('utf-8')).decode('utf-8')
        with open(hex_user_id + "_config.json",  'wt') as user_config_file:
            json.dump(user_config, user_config_file)

    def __prove_activation_pin(self, activation_pin):
        s = requests.Session()
        SRP = CustomSRP()

        randomA = SRP.SRPStage1()
        r = s.post("https://www.mitid.dk/mitid-code-app-regi/v1/activation/init", json={"userId": self.user_id, "type": "ACTIVATION", "randomA": {"value": randomA}})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when starting pin activation process")
        
        r = r.json()
        srp_salt = r["srpSalt"]["value"]
        randomB = r["randomB"]["value"]
        pbkdf2_salt = r["pbkdf2Salt"]["value"]
        activation_session_id = r["activationSessionId"]

        m1 = SRP.SRPStage3(srp_salt, randomB, pbkdf2_salt, activation_pin, activation_session_id)

        r = s.post("https://www.mitid.dk/mitid-code-app-regi/v1/activation/"+activation_session_id+"/password-prove", json={"m1": { "value": m1 }})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when proving during pin activation process")
        r = r.json()

        m2 = r["m2"]["value"]
        if not SRP.SRPStage5(m2):
            raise Exception("m2 could not be validated during proving of activation pin")
        encrypted_message = r["encMessage"]
        decrypted = json.loads(SRP.AuthDec(encrypted_message))
        self.authenticator_id = decrypted["authenticatorId"]
        print(f'Beginning registration of authenticator "{decrypted["authenticatorId"]}" with assurance level (AEL) of "{decrypted["AEL"]}"')

        print("Generating key pairs, this may take a little time...")
        self.ecc_key = ECC.generate(curve='secp256r1')
        affineX = int(self.ecc_key.public_key().pointQ.x)
        affineY = int(self.ecc_key.public_key().pointQ.y)
        affineX = affineX.to_bytes((affineX.bit_length() + 7) // 8, 'big')
        affineY = affineY.to_bytes((affineY.bit_length() + 7) // 8, 'big')

        self.rsa_key = RSA.generate(3072)
        rsa_modulus = self.rsa_key.public_key().n
        rsa_modulus_bytes = rsa_modulus.to_bytes((rsa_modulus.bit_length() + 7) // 8, 'big')

        bks_keystore_password = base64.b64encode(Random.new().read(32)).decode("utf-8")
        self.app_instance_id = str(uuid.uuid4())

        extra_enrolment_data = {
            "board": "",
            "brand": "",
            "buildNumber": "",
            "device": "",
            "hardware": "",
            "id": "",
            "manufacturer": "",
            "osApiLevel": "",
            "packageName": self.constants["packageName"],
            "product": "",
            "sn": "",
            "strongBox": True,
            "versionIncremental": "",
        }

        enrolment_data = {
            "deviceMetrics": {
                "osName": self.constants["osName"],
                "osVersion": self.constants["osVersion"],
                "jailbrokenStatus": False,
                "model": self.constants["model"],
                "swFingerprint": self.constants["swFingerprint"],
                "hwGenKey": True,
                "sdkVersion": self.constants["sdkVersion"],
                "appInstanceId": self.app_instance_id,
                "appIdent": self.constants["packageName"] + ".release",
                "appVersion": self.constants["sdkVersion"] + "." + self.constants["versionCode"],
                "appName": self.constants["appName"],
                "extra": json.dumps(extra_enrolment_data)
            },
            "rsaPublicKey": base64.b64encode(rsa_modulus_bytes).decode("utf-8"),
            "eccPublicKey": base64.b64encode(affineX + affineY).decode("utf-8"),
            "R": bks_keystore_password,
            "fcmToken": "" # Firebase token, may be hard without an android device
        }
        enrolment_data_json_bytes = json.dumps(enrolment_data).encode("utf-8")
        encrypted_enrolment_data = base64.b64encode(SRP.EncWithKBits(enrolment_data_json_bytes)).decode("utf-8")

        # I believe this is supposed to be a list of "risky" apps on the users device
        encrypted_device_apps = base64.b64encode(SRP.EncWithKBits(json.dumps([]).encode("utf-8"))).decode("utf-8")

        # This is supposed be the enrolment_data(i think, some stuff put together anyways) signed by google's play integrity API
        # This check has been enabled, see (https://digst.dk/nyheder/nyhedsarkiv/2024/juni/mitid-faar-ekstra-antisvindel-mekanisme/), and now prevents the ability to sign up a custom authenticator with MitID's servers, as enc_play_integrity needs to be signed by google as belonging
        # to a real Android device running the real MitID app. It may be possible to work towards fooling this check, but there is probably a lot of work in it.
        enc_play_integrity = None

        r = s.post("https://www.mitid.dk/mitid-code-app-regi/v1/activation/"+activation_session_id+"/enrol", json={"encDeviceApps": encrypted_device_apps, "encEnrolmentData": encrypted_enrolment_data, "encPlayIntegrity": enc_play_integrity})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when enrolling during pin activation process")
        r = r.json()

        encrypted_message = r["encMessage"]
        decrypted = json.loads(SRP.AuthDec(encrypted_message))
        print(f'You are registering authenticator "{decrypted["authenticatorId"]}" for "{decrypted["personalInfo"]["identityName"]}"')
        self.auth_seed = binascii.unhexlify(decrypted["authSeed"])

    def __prove_temporary_pin(self, temporary_pin):
        s = requests.Session()
        SRP = CustomSRP()
        randomA = SRP.SRPStage1()

        r = s.post("https://www.mitid.dk/mitid-code-app-regi/v2/activation/"+self.authenticator_id+"/pin-init", headers=self.__generate_auth_headers(), json={"randomA": {"value": randomA}})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when starting temporary pin process")
        r = r.json()
        srp_salt = r["srpSalt"]["value"]
        randomB = r["randomB"]["value"]
        pbkdf2_salt = r["pbkdf2Salt"]["value"]

        m1 = SRP.SRPStage3(srp_salt, randomB, pbkdf2_salt, temporary_pin, self.authenticator_id)

        r = s.post("https://www.mitid.dk/mitid-code-app-regi/v2/activation/"+self.authenticator_id+"/pin-prove", headers=self.__generate_auth_headers(), json={"m1": {"value": m1}})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when proving temporary pin")
        r = r.json()

        m2 = r["m2"]["value"]
        if not SRP.SRPStage5(m2):
            raise Exception("m2 could not be validated during proving of activation pin")
        return SRP
    
    def __trim_zero(self, bytes_to_trim):
        if bytes_to_trim[0] == b'\x00':
            return bytes_to_trim[1:]
        return bytes_to_trim

    def __register_authenticator_using_verifier(self, SRP):
        self.client_salt = hex(random.getrandbits(256))[2:]
        srp_salt = random.getrandbits(256)
        srp_salt_bytes = self.__trim_zero(srp_salt.to_bytes((srp_salt.bit_length() + 7) // 8, 'big'))
        pbkdf2_salt = random.getrandbits(256)
        pbkdf2_salt_bytes = self.__trim_zero(pbkdf2_salt.to_bytes((pbkdf2_salt.bit_length() + 7) // 8, 'big'))

        m = hashlib.sha256()
        m.update(self.pin.encode('utf-8') + self.client_salt.encode('utf-8'))
        verifier_step_1 = m.digest()

        verifier_step_2 = PBKDF2(str(int.from_bytes(verifier_step_1, byteorder='big')), pbkdf2_salt_bytes, 32, count=20000, hmac_hash_module=SHA256)

        m = hashlib.sha256()
        m.update(binascii.hexlify(srp_salt_bytes) + binascii.hexlify(verifier_step_2))
        verifier_step_3 = m.digest()

        verifier = pow(SRP.g, int.from_bytes(verifier_step_3, byteorder='big'), SRP.N)


        enrolment_data = {
            "verifier": hex(verifier)[2:],
            "salt": hex(srp_salt)[2:],
            "pbkdf2Salt": hex(pbkdf2_salt)[2:],
            "clientSalt": int(self.client_salt, 16)
        }
        enrolment_data_json_bytes = json.dumps(enrolment_data).encode("utf-8")
        encrypted_enrolment_data = base64.b64encode(SRP.EncWithKBits(enrolment_data_json_bytes)).decode("utf-8")

        r = requests.post("https://www.mitid.dk/mitid-code-app-regi/v2/activation/"+self.authenticator_id+"/verifier", headers=self.__generate_auth_headers(), json={"encEnrolmentData": encrypted_enrolment_data})
        if(r.status_code != 204):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when registering final pin using verifier")

    def register_authenticator(self):
        activation_pin = input("Type activation pin\n").strip()
        self.__prove_activation_pin(activation_pin)

        temp_rsa_key = RSA.generate(3072)
        new_rsa_modulus = temp_rsa_key.public_key().n
        new_rsa_modulus_bytes = new_rsa_modulus.to_bytes((new_rsa_modulus.bit_length() + 7) // 8, 'big')

        r = requests.post("https://www.mitid.dk/mitid-code-app-regi/v1/activation/"+self.authenticator_id+"/temp-pin", headers=self.__generate_auth_headers(), json={"language": "en", "tempPinRsaPublicKey": base64.b64encode(new_rsa_modulus_bytes).decode("utf-8")})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when requesting temporary pin")
        r = r.json()
        # These two are entirely user informational (phone number, etc)
        encrypted_aes_key = base64.b64decode(r["encKey"])
        encrypted_message = base64.b64decode(r["encMsg"])

        rsa_cipher = PKCS1_OAEP.new(temp_rsa_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)

        aes_cipher = AES.new(aes_key, AES.MODE_GCM, encrypted_message[:BLOCK_SIZE])
        decrypted = aes_cipher.decrypt(encrypted_message[BLOCK_SIZE:len(encrypted_message)-BLOCK_SIZE])

        phoneNumberInfo = json.loads(decrypted)
        print(f'A temporary pin will now be sent to (+{phoneNumberInfo["countryCallingCode"]}) {phoneNumberInfo["phoneNumber"]}')

        temporary_pin = input("Type temporary pin, received in SMS\n").strip()
        SRP = self.__prove_temporary_pin(temporary_pin)

        self.pin = input("Type your desired authenticator pin, 6 digits\n").strip()
        self.__register_authenticator_using_verifier(SRP)
        self.user_exists = True
        self.__save_authenticator()
        print("Your authenticator is now registered as: " + self.authenticator_id)

    def can_authenticate(self):
        return self.user_exists

    def __generate_auth_headers(self):
        apk_signing_public_key_bytes = binascii.unhexlify(self.constants["apkSigningKey"])
        m = hashlib.sha256()
        m.update(apk_signing_public_key_bytes)
        apk_signing_public_key_digest = m.digest()
        
        current_time_milliseconds = int(time.time() * 1000)
        current_time = (current_time_milliseconds // 100000000)
        current_time_bytes = current_time.to_bytes(8, 'big')

        m = hashlib.sha256()
        m.update(self.auth_seed + apk_signing_public_key_digest + current_time_bytes)
        auth_key_bytes = m.digest()

        headers = {
            "auth-id": self.authenticator_id,
            "authKey": base64.b64encode(auth_key_bytes).decode("utf-8"),
            "timestamp": str(current_time_milliseconds)
        }

        return headers

    def __get_pin_binding(self, ticket):
        s = requests.Session()
        SRP = CustomSRP()
        randomA = SRP.SRPStage1()
        r = s.post("https://www.mitid.dk/mitid-code-app-auth/v1/authenticator-sessions/app/"+self.authenticator_id+"/init",  json={"ticket": ticket, "randomA": { "value": randomA }})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when starting get pin binding process")
        
        r = r.json()
        srp_salt = r["srpSalt"]["value"]
        randomB = r["randomB"]["value"]
        pbkdf2_salt = r["pbkdf2Salt"]["value"]

        m = hashlib.sha256()
        m.update((self.pin + self.client_salt).encode('utf-8'))
        pin_digest = m.digest()
        m1 = SRP.SRPStage3(srp_salt, randomB, pbkdf2_salt, str(int.from_bytes(pin_digest, byteorder='big')), ticket)

        m = hashlib.sha256()
        m.update(("flowValues" + binascii.hexlify(SRP.K_bits).decode('utf-8')).encode('utf-8'))
        flow_values_digest = m.digest()
        flow_value_proof = hmac.new(flow_values_digest, (self.authenticator_id + "," + ticket).encode('utf8'), hashlib.sha256).hexdigest()

        r = s.post("https://www.mitid.dk/mitid-code-app-auth/v1/authenticator-sessions/app/"+self.authenticator_id+"/pin-prove",  json={"ticket": ticket, "flowValueProof": { "value": flow_value_proof }, "m1": { "value": m1 }})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when proving during get pin binding process")
        r = r.json()
        enc_message = r["encMessage"]
        message = SRP.AuthDecPin(enc_message)
        pin_binding = message[:32]
        # bks_password is used in the offical implementation to password-gate the RSA key in a BKS keystore
        # bks_password = base64.b64decode(message[32:]) 
        return pin_binding

    def __extract_response_and_sign_it(self, msg, datagram, pin_binding):
        if len(datagram) != 737:
            raise Exception("Request datagram had invalid length")
        datagram_version_byte = datagram[0]
        # Only one value allowed in the official implementation as well
        if datagram_version_byte != 1:
            raise Exception("Invalid datagram version")
        response_iv = datagram[1:1+16]
        encrypted_response_data = datagram[17:17+80]
        encrypted_aes_key = datagram[97:97+384]
        hsm_signature = datagram[97+384:97+384+256]

        cipher = PKCS1_OAEP.new(self.rsa_key)
        aes_key = cipher.decrypt(encrypted_aes_key)

        # Precise algorithm in the original implementation: AES/CBC/PKCS5PADDING
        # Weird choice, seems outdated
        cipher = AES.new(aes_key, AES.MODE_CBC, response_iv)
        response_data = unpad(cipher.decrypt(encrypted_response_data))

        requests_public_key = RSA.import_key(base64.b64decode(self.constants["requestSigningKey"]))
        h = SHA256.new(datagram_version_byte.to_bytes(1, 'big') + response_data)
        try:
            pkcs1_15.new(requests_public_key).verify(h, hsm_signature)
        except (ValueError, TypeError):
            raise Exception("HSM signature is not valid")
        
        response = response_data[:32]
        # expiration_time = response_data[32:40]
        tx_id = response_data[40:44]
        msg_encryption_key = response_data[44:76]

        cipher = AES.new(msg_encryption_key, AES.MODE_GCM, msg[:16], mac_len=16)
        msg = cipher.decrypt(msg[16:len(msg)-16])
        msg_split = str(msg).split(',')
        broker_security = msg_split[1]
        reference_text_header = msg_split[2]
        reference_text_body = msg_split[3]
        serviceProvider = msg_split[4]

        print(f'Authenticating MitID request "{base64.b64decode(reference_text_header).decode("utf-8")}" with text "{base64.b64decode(reference_text_body).decode("utf-8")}" for service provider "{base64.b64decode(serviceProvider).decode("utf-8")}"')

        m = hashlib.sha256()
        m.update(response + broker_security.encode('utf-8') + reference_text_header.encode('utf-8') + reference_text_body.encode('utf-8') + pin_binding)
        response_to_sign = m.digest()

        h = SHA256.new(tx_id + response_to_sign)
        signer = DSS.new(self.ecc_key, 'fips-186-3', encoding='der')
        signed_response = signer.sign(h)

        return base64.b64encode(response).decode('utf-8'), base64.b64encode(signed_response).decode('utf-8')

    def authenticate_request(self):
        r = requests.post("https://www.mitid.dk/mitid-code-app-state-notifier/pull", headers=self.__generate_auth_headers(), json={"codeAppSerialNumber": self.authenticator_id})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when polling for new authentication sessions")
        
        r = r.json()
        status = r["status"]

        if(status == "NOTFOUND"):
            print("No authentication session in progress")
            return
        
        ticket = r["ticket"]
        msg = base64.b64decode(r["msg"]["msg"])
        datagram = base64.b64decode(r["msg"]["datagram"])

        pin_binding = self.__get_pin_binding(ticket)

        response, signed_response = self.__extract_response_and_sign_it(msg, datagram, pin_binding)

        confirmation = {
            "codeAppSerialNumber": self.authenticator_id,
            "ticket": ticket,
            "confirmed": True,
            "performanceMeasurements": None,
            "payload": {
                "response": response,
                "responseSignature": signed_response
            }
        }
        r = requests.post("https://www.mitid.dk/mitid-code-app-state-notifier/confirm", headers=self.__generate_auth_headers(), json=confirmation)
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when confirming authentication session '" + self.ticket + "'")
        
        r = r.json()
        status = r["status"]
        if(status != "OK"):
            print("Could not confirm authentication session, status: " + status)
            return

        print("Authenticated MitID request: " + ticket)

    def revoke_authenticator(self):
        s = requests.Session()

        r = s.put(f"https://www.mitid.dk/mitid-code-app-regi/v1/authenticators/{self.authenticator_id}/state", headers=self.__generate_auth_headers(), json={"state": "REVOKED"})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when revoking authenticator")

    def get_authenticator_state(self):
        s = requests.Session()

        salt = Random.new().read(32)
        salt_base64 = base64.b64encode(salt).decode("utf-8")

        intermediary_key = hmac.new(salt, self.auth_seed, hashlib.sha256).digest()

        static_bytes = "device_metrics_hash".encode('utf-8') + (1).to_bytes(1, 'big')

        final_key = hmac.new(intermediary_key, static_bytes, hashlib.sha256).digest()

        extra_device_data = {
            "board": "",
            "brand": "",
            "buildNumber": "",
            "device": "",
            "hardware": "",
            "id": "",
            "manufacturer": "",
            "osApiLevel": "",
            "packageName": self.constants["packageName"],
            "product": "",
            "sn": "",
            "strongBox": True,
            "versionIncremental": "",
        }

        device_data = {
            "deviceMetrics": {
                "osName": self.constants["osName"],
                "osVersion": self.constants["osVersion"],
                "jailbrokenStatus": False,
                "model": self.constants["model"],
                "swFingerprint": self.constants["swFingerprint"],
                "hwGenKey": True,
                "sdkVersion": self.constants["sdkVersion"],
                "appInstanceId": self.app_instance_id,
                "appIdent": self.constants["packageName"] + ".release",
                "appVersion": self.constants["sdkVersion"] + "." + self.constants["versionCode"],
                "appName": self.constants["appName"],
                "extra": json.dumps(extra_device_data)
            },
            "fcmToken": "" # Firebase token, may be hard without an android device
        }
        device_data_json_bytes = json.dumps(device_data).encode("utf-8")

        iv = Random.new().read(16)
        cipher = AES.new(final_key, AES.MODE_GCM, iv)
        ciphertext, tag = cipher.encrypt_and_digest(device_data_json_bytes)
        encrypted_device_data = (iv + ciphertext + tag)
        encrypted_device_data_base64 = base64.b64encode(encrypted_device_data).decode("utf-8")

        headers = self.__generate_auth_headers()
        headers["salt"] = salt_base64

        # Use the below call for updating the Authenticator information
        #r = s.put(f"https://www.mitid.dk/mitid-code-app-regi/v3/authenticators/{self.authenticator_id}/devicemetric/", headers=headers, json={"encDeviceData": encrypted_device_data_base64, "lang": "en"})
        r = s.put(f"https://www.mitid.dk/mitid-code-app-regi/v3/authenticators/{self.authenticator_id}/devicemetric/", headers=headers, json={"lang": "en"})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when starting pin activation process")
        
        r = r.json()
        return r


    def request_activation_pin(self, short_code = False):
        authenticator_state = self.get_authenticator_state()
        now = datetime.now(timezone.utc)
        if authenticator_state["changeProfileType"] == "ACTIVATION_CODE" and authenticator_state["profileChangeFrom"] != None and datetime.strptime(authenticator_state["profileChangeFrom"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc) > now:
            seconds_difference = (datetime.strptime(authenticator_state["profileChangeFrom"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc) - now).total_seconds()
            minutes_left = int(seconds_difference / 60)
            seconds_left = int(seconds_difference % 60)
            print(f"Waiting for profile change window to open, {minutes_left} minutes and {seconds_left} seconds left")
            return

        s = requests.Session()
        SRP = CustomSRP()

        randomA = SRP.SRPStage1()
        r = s.post(f"https://www.mitid.dk/mitid-code-app-regi/v1/pinchange/{self.authenticator_id}/pin-init", headers=self.__generate_auth_headers(), json={"randomA": {"value": randomA}})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when starting pin activation process")
        
        r = r.json()
        srp_salt = r["srpSalt"]["value"]
        randomB = r["randomB"]["value"]
        pbkdf2_salt = r["pbkdf2Salt"]["value"]

        m = hashlib.sha256()
        m.update((self.pin + self.client_salt).encode('utf-8'))
        pin_digest = m.digest()

        m1 = SRP.SRPStage3(srp_salt, randomB, pbkdf2_salt, str(int.from_bytes(pin_digest, byteorder='big')), self.authenticator_id)

        r = s.post(f"https://www.mitid.dk/mitid-code-app-regi/v1/pinchange/{self.authenticator_id}/pin-prove", headers=self.__generate_auth_headers(), json={"m1": { "value": m1 }, "context": "PROFILE_ACTIVATION"})
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            raise Exception("Error when proving during pin activation process")
        r = r.json()

        m2 = r["m2"]["value"]
        if not SRP.SRPStage5(m2):
            raise Exception("m2 could not be validated during proving of activation pin")

        if authenticator_state["changeProfileType"] != "ACTIVATION_CODE" or authenticator_state["profileChangeFrom"] == None:
            r = requests.put(f"https://www.mitid.dk/mitid-code-app-regi/v1/profile/{self.authenticator_id}", headers=self.__generate_auth_headers(), json={"encProfileData": None, "profileData": { "channelBindingType": None,"requestChange": True, "requestChangeTo": "ACTIVATION_CODE" }})
            if(r.status_code != 200):
                print(r.status_code)
                print(r.content)
                print(r.headers)
                raise Exception("Error when starting get pin binding process")
            
            r = r.json()
            print(r)
            return
        
        activation_request = {
            "requestActivationCode": {
                "activationCodeGenerationType": "SHORT" if short_code else "LONG"
            }
        }
        activation_request_json_bytes = json.dumps(activation_request).encode("utf-8")
        encrypted_activation_request = base64.b64encode(SRP.EncWithKBits(activation_request_json_bytes)).decode("utf-8")

        r = requests.put(f"https://www.mitid.dk/mitid-code-app-regi/v1/profile/{self.authenticator_id}", headers=self.__generate_auth_headers(), json={"encProfileData": encrypted_activation_request })
        if(r.status_code != 200):
            print(r.status_code)
            print(r.content)
            print(r.headers)
            raise Exception("Error when starting get pin binding process")
        
        r = r.json()
        print(f"Your activation code is '{r['requestActivationCodeResponse']['activationCode']}', it will expire in 3 minutes")


parser = argparse.ArgumentParser(description="argparser")
parser.add_argument('--generateActivationCode', action=argparse.BooleanOptionalAction)
parser.add_argument('--getAuthenticatorState', action=argparse.BooleanOptionalAction)
parser.add_argument('--revoke', action=argparse.BooleanOptionalAction)
args = parser.parse_args()

authenticator = Authenticator("INSERT-MITID-USERNAME-HERE")

if args.generateActivationCode:
    authenticator.request_activation_pin()
elif args.getAuthenticatorState:
    print(authenticator.get_authenticator_state())
elif args.revoke:
    print(authenticator.revoke_authenticator())
elif authenticator.can_authenticate():
    authenticator.authenticate_request()
else:
    authenticator.register_authenticator()
