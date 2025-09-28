class NinebotCrypto {
    constructor(name) {
        this._name = new Uint8Array(16);
        this._random_ble_data = new Uint8Array(16);
        this._random_app_data = new Uint8Array(16);
        this._fw_data = new Uint8Array(16); // should be set from firmware
        this._sha1_key = new Uint8Array(16);
        this._msg_it = 0;
        for (let i = 0; i < name.length && i < 16; i++) this._name[i] = name.charCodeAt(i);
        this.calcSha1Key(this._name, this._fw_data);
    }

    async sha1(data) {
        let hash = await crypto.subtle.digest('SHA-1', data);
        return new Uint8Array(hash);
    }

    xor16(a, b) {
        let out = new Uint8Array(16);
        for (let i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
        return out;
    }

    async aesEcbEncrypt(data, key) {
        const cryptoKey = await crypto.subtle.importKey("raw", key, {name:"AES-ECB"}, false, ["encrypt"]);
        return new Uint8Array(await crypto.subtle.encrypt({name:"AES-ECB"}, cryptoKey, data));
    }

    async calcSha1Key(data1, data2) {
        let buf = new Uint8Array(32);
        buf.set(data1, 0);
        buf.set(data2, 16);
        let hash = await this.sha1(buf);
        this._sha1_key.set(hash.slice(0,16));
    }

    async CryptoFirst(data) {
        let result = new Uint8Array(data.length);
        let payload_len = data.length;
        let byte_idx = 0;
        while (payload_len > 0) {
            let tmp_len = Math.min(16, payload_len);
            let xor_data_1 = new Uint8Array(16);
            xor_data_1.set(data.slice(byte_idx, byte_idx + tmp_len));
            let aes_key = await this.aesEcbEncrypt(this._fw_data, this._sha1_key);
            let xor_data_2 = aes_key;
            let xor_data = this.xor16(xor_data_1, xor_data_2);
            result.set(xor_data.slice(0,tmp_len), byte_idx);
            payload_len -= tmp_len;
            byte_idx += tmp_len;
        }
        return result;
    }

    async CryptoNext(data, msgIt) {
        let result = new Uint8Array(data.length);
        let aes_enc_data = new Uint8Array(16);
        aes_enc_data[0] = 1;
        aes_enc_data[1] = (msgIt >> 24) & 0xFF;
        aes_enc_data[2] = (msgIt >> 16) & 0xFF;
        aes_enc_data[3] = (msgIt >> 8) & 0xFF;
        aes_enc_data[4] = (msgIt) & 0xFF;
        aes_enc_data.set(this._random_ble_data.slice(0,8),5);
        aes_enc_data[15] = 0;

        let payload_len = data.length;
        let byte_idx = 0;

        while (payload_len > 0) {
            aes_enc_data[15]++;
            let tmp_len = Math.min(16, payload_len);
            let xor_data_1 = new Uint8Array(16);
            xor_data_1.set(data.slice(byte_idx, byte_idx + tmp_len));
            let aes_key = await this.aesEcbEncrypt(aes_enc_data, this._sha1_key);
            let xor_data = this.xor16(xor_data_1, aes_key);
            result.set(xor_data.slice(0,tmp_len), byte_idx);
            payload_len -= tmp_len;
            byte_idx += tmp_len;
        }
        return result;
    }

    CalcCrcFirstMsg(data) {
        let crc = 0;
        for (let v of data) crc += v;
        crc = ~crc & 0xFFFF;
        return new Uint8Array([crc & 0xFF, (crc>>8)&0xFF]);
    }

    async CalcCrcNextMsg(data, msgIt) {
        let aes_enc_data = new Uint8Array(16);
        let payload_len = data.length - 3;
        let byte_idx = 3;
        aes_enc_data[0] = 89;
        aes_enc_data[1] = (msgIt >> 24)&0xFF;
        aes_enc_data[2] = (msgIt >> 16)&0xFF;
        aes_enc_data[3] = (msgIt >> 8)&0xFF;
        aes_enc_data[4] = (msgIt)&0xFF;
        aes_enc_data.set(this._random_ble_data.slice(0,8),5);
        aes_enc_data[15] = payload_len;

        let aes_key = await this.aesEcbEncrypt(aes_enc_data, this._sha1_key);
        let xor_data_2 = aes_key;

        let xor_data_1 = new Uint8Array(16);
        xor_data_1.set(data.slice(0,3));
        let xor_data = this.xor16(xor_data_1, xor_data_2);
        aes_key = await this.aesEcbEncrypt(xor_data, this._sha1_key);
        xor_data_2 = aes_key;

        while (payload_len > 0) {
            let tmp_len = Math.min(16,payload_len);
            xor_data_1 = new Uint8Array(16);
            xor_data_1.set(data.slice(byte_idx, byte_idx+tmp_len));
            xor_data = this.xor16(xor_data_1, xor_data_2);
            aes_key = await this.aesEcbEncrypt(xor_data, this._sha1_key);
            xor_data_2 = aes_key;
            payload_len -= tmp_len;
            byte_idx += tmp_len;
        }

        aes_enc_data[0]=1; aes_enc_data[15]=0;
        aes_key = await this.aesEcbEncrypt(aes_enc_data, this._sha1_key);
        xor_data_1 = aes_key;
        xor_data = this.xor16(xor_data_1, xor_data_2);
        return xor_data.slice(0,4);
    }

    async Encrypt(data) {
        let encrypted = new Uint8Array(152);
        encrypted.set(data.slice(0,3),0);
        let payload = data.slice(3);
        if(this._msg_it==0){
            let crc = this.CalcCrcFirstMsg(payload);
            payload = await this.CryptoFirst(payload);
            encrypted.set(payload,3);
            encrypted[payload.length+3] = 0;
            encrypted[payload.length+4] = 0;
            encrypted[payload.length+5] = crc[0];
            encrypted[payload.length+6] = crc[1];
            encrypted[payload.length+7] = 0;
            encrypted[payload.length+8] = 0;
            encrypted = encrypted.slice(0,payload.length+9);
            this._msg_it++;
        } else {
            this._msg_it++;
            let crc = await this.CalcCrcNextMsg(data,this._msg_it);
            payload = await this.CryptoNext(payload,this._msg_it);
            encrypted.set(payload,3);
            encrypted[payload.length+3] = crc[0];
            encrypted[payload.length+4] = crc[1];
            encrypted[payload.length+5] = crc[2];
            encrypted[payload.length+6] = crc[3];
            encrypted[payload.length+7] = (this._msg_it>>8)&0xFF;
            encrypted[payload.length+8] = (this._msg_it)&0xFF;
            encrypted = encrypted.slice(0,payload.length+9);
            if(data[0]==0x5A && data[1]==0xA5 && data[2]==0x10 && data[3]==0x3E && data[4]==0x21 && data[5]==0x5C && data[6]==0x00){
                this._random_app_data.set(data.slice(7,23));
            }
        }
        return encrypted;
    }

    async Decrypt(data) {
        let decrypted = new Uint8Array(data.length-6);
        decrypted.set(data.slice(0,3));
        let new_msg_it = this._msg_it;
        if((new_msg_it & 0x0008000) && (data[data.length-2]>>7)==0) new_msg_it+=0x0010000;
        new_msg_it = (new_msg_it & 0xFFFF0000) + (data[data.length-2]<<8) + data[data.length-1];
        let payload_len = data.length-9;
        let payload = data.slice(3,3+payload_len);

        if(new_msg_it==0){
            payload = await this.CryptoFirst(payload);
            decrypted.set(payload,3);
            if(decrypted[0]==0x5A && decrypted[1]==0xA5 && decrypted[2]==0x1E && decrypted[3]==0x21 && decrypted[4]==0x3E && decrypted[5]==0x5B){
                this._random_ble_data.set(decrypted.slice(7,23));
                await this.calcSha1Key(this._name,this._random_ble_data);
            }
        } else if(new_msg_it>0 && new_msg_it>this._msg_it){
            payload = await this.CryptoNext(payload,new_msg_it);
            decrypted.set(payload,3);
            if(decrypted[0]==0x5A && decrypted[1]==0xA5 && decrypted[2]==0x00 && decrypted[3]==0x21 && decrypted[4]==0x3E && decrypted[5]==0x5C && decrypted[6]==0x01){
                await this.calcSha1Key(this._random_app_data,this._random_ble_data);
            }
            this._msg_it=new_msg_it;
        }
        return decrypted;
    }
}
