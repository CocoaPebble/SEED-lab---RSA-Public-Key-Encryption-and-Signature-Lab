#include "RSA.c"

int hex_to_int(char c)
{
    if (c >= 97)
        c = c - 32;
    int first = c / 16 - 3;
    int second = c % 16;
    int result = first * 10 + second;
    if (result > 9)
        result--;
    return result;
}

int hex_to_ascii(const char c, const char d)
{
    int high = hex_to_int(c) * 16;
    int low = hex_to_int(d);
    return high + low;
}

void printBN(char *msg, BIGNUM *a)
{
    /* Use BN_bn2hex(a) for hex string
     * Use BN_bn2dec(a) for decimal string */
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

void printHX(const char *st)
{
    int length = strlen(st);
    if (length % 2 != 0)
    {
        printf("%s\n", "invalid hex length");
        return;
    }
    int i;
    char buf = 0;
    for (i = 0; i < length; i++)
    {
        if (i % 2 != 0)
            printf("%c", hex_to_ascii(buf, st[i]));
        else
            buf = st[i];
    }
    printf("\n");
}

int main()
{
    /*
        Task 1: Deriving the Private Key
    */

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();

    // Assign values to p, q, e
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    // Calculate d as private key, d = e^-1 mod (p-1)(q-1)
    BIGNUM *priv_key = get_rsa_priv_key(p, q, e);
    printBN("Private Key in task 1 is: ", priv_key);
    printf("\n");
    /*
        Task 2: Encrypting a Message
    */

    // Assign private key d
    BIGNUM *private_key_d = BN_new();
    BN_hex2bn(&private_key_d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // Assign public key n
    BIGNUM *public_key_n = BN_new();
    BN_hex2bn(&public_key_n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    printBN("Public Key in task 2 is: ", public_key_n);

    // Assign Modulus e
    BIGNUM *modulus_e = BN_new();
    BN_hex2bn(&modulus_e, "010001");

    // Encrypt the message "A top secret!", convert to hex, then convert to BIGNUM
    BIGNUM *message = BN_new();
    BN_hex2bn(&message, "4120746f702073656372657421");
    printBN("Message in task 2 is: ", message);

    // Encrypt the message using RSA
    BIGNUM *encrypted_message = rsa_encrypt(message, private_key_d, public_key_n);
    printBN("Encrypted Message in task 2 is: ", encrypted_message);
    // Decrypt the message using RSA
    BIGNUM *decrypted_message = rsa_decrypt(encrypted_message, modulus_e, public_key_n);
    printBN("Decrypted Message in task 2 is: ", decrypted_message);

    printf("\n");

    /*
        Task 3: Decrypting a Message
    */

    BIGNUM *ciphertext = BN_new();
    BN_hex2bn(&ciphertext, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    // Decrypt the message using RSA
    BIGNUM *decrypted_message_task3 = rsa_decrypt(ciphertext, private_key_d, public_key_n);
    printf("Decrypted Message in task 3 is: ");
    printHX(BN_bn2hex(decrypted_message_task3));
    printf("\n");

    /*
        Task 4: Signing a Message
    */

    // pub key and priv key are the same as task 2
    // message is "I owe you $2000.", convert to hex, then convert to BIGNUM
    BIGNUM *message_task4 = BN_new();
    BN_hex2bn(&message_task4, "49206F776520796F752024323030302E");

    // Encrypt the message using RSA
    BIGNUM *encrypted_message_task4 = rsa_encrypt(message_task4, private_key_d, public_key_n);
    printBN("Signature in task 4 is: ", encrypted_message_task4);

    // Modify the message to "I owe you $3000.", convert to hex, then convert to BIGNUM
    BIGNUM *message_task4_modified = BN_new();
    BN_hex2bn(&message_task4_modified, "49206F776520796F752024333030302E");
    BIGNUM *modified_encrypted_message_task4 = rsa_encrypt(message_task4_modified, private_key_d, public_key_n);
    printBN("Signature modified in task 4 is: ", modified_encrypted_message_task4);

    printf("\n");

    /*
        Task 5: Verifying a Signature
    */

    // M = "Launch a missile."
    BIGNUM *message_task_5 = BN_new();
    BN_hex2bn(&message_task_5, "4C61756E63682061206D697373696C652E");
    // Alice public key (e, n), e = 010001, n = AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115
    BIGNUM *alice_public_key_n = BN_new();
    BN_hex2bn(&alice_public_key_n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

    // signature S = 643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F
    BIGNUM *S = BN_new();
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

    // Decrypt the signature using RSA
    BIGNUM *decrypted_signature = rsa_decrypt(S, modulus_e, alice_public_key_n);
    printf("Decrypted signature in task 5 is: ");
    printHX(BN_bn2hex(decrypted_signature));
    printf("\n");
    // corrupted signature S' = 643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F
    BIGNUM *S2 = BN_new();
    BN_hex2bn(&S2, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    // Decrypt the signature using RSA
    BIGNUM *decrypted_signature2 = rsa_decrypt(S2, modulus_e, alice_public_key_n);
    printf("Corrputed signature in task 5 is: ");
    printHX(BN_bn2hex(decrypted_signature2));

    printf("\n");

    /*
        Task 6: Manually Verifying an X.509 Certificate
    */

    // extracted the public key and modulus from the certificate at example.com
    // pub key
    BIGNUM *pub_key_task_6 = BN_new();
    BN_hex2bn(&pub_key_task_6, "B6E02FC22406C86D045FD7EF0A6406B27D22266516AE42409BCEDC9F9F76073EC330558719B94F940E5A941F5556B4C2022AAFD098EE0B40D7C4D03B72C8149EEF90B111A9AED2C8B8433AD90B0BD5D595F540AFC81DED4D9C5F57B786506899F58ADAD2C7051FA897C9DCA4B182842DC6ADA59CC71982A6850F5E44582A378FFD35F10B0827325AF5BB8B9EA4BD51D027E2DD3B4233A30528C4BB28CC9AAC2B230D78C67BE65E71B74A3E08FB81B71616A19D23124DE5D79208AC75A49CBACD17B21E4435657F532539D11C0A9A631B199274680A37C2C25248CB395AA2B6E15DC1DDA020B821A293266F144A2141C7ED6D9BF2482FF303F5A26892532F5EE3");
    // modulus
    BIGNUM *modulus_task_6 = modulus_e;

    // signature
    BIGNUM *signature_task_6 = BN_new();
    BN_hex2bn(&signature_task_6, "84a89a11a7d8bd0b267e52247bb2559dea30895108876fa9ed10ea5b3e0bc72d47044edd4537c7cabc387fb66a1c65426a73742e5a9785d0cc92e22e3889d90d69fa1b9bf0c16232654f3d98dbdad666da2a5656e31133ece0a5154cea7549f45def15f5121ce6f8fc9b04214bcf63e77cfcaadcfa43d0c0bbf289ea916dcb858e6a9fc8f994bf553d4282384d08a4a70ed3654d3361900d3f80bf823e11cb8f3fce7994691bf2da4bc897b811436d6a2532b9b2ea2262860da3727d4fea573c653b2f2773fc7c16fb0d03a40aed01aba423c68d5f8a21154292c034a220858858988919b11e20ed13205c045564ce9db365fdf68f5e99392115e271aa6a8882");

    // decrypt the signature using the public key and modulus given from the certificate
    BIGNUM *decrypted_signature_task_6 = rsa_decrypt(signature_task_6, modulus_task_6, pub_key_task_6);
    printBN("Decrypted signature in task 6 is: ", decrypted_signature_task_6);
    printf("\n");

    printf("the pre-computed hash was: ");
    printf("902677e610fedcdd34780e359692eb7bd199af35115105636aeb623f9e4dd053");
    printf("\n");
}