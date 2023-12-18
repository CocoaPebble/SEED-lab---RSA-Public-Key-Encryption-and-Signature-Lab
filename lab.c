

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
    printBN("Decrypted Message in task 3 is: ");
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
    BIGNUM *encrypted_message_task4 = rsa_encrypt(message_task4_modified, private_key_d, public_key_n);
    printBN("Signature modified in task 4 is: ", encrypted_message_task4);

    printf("\n");

    /*
        Task 5: Verifying a Signature
    */

    // M = "Launch a missile."
    BIGNUM* message_task_5 = BN_new();
    BN_hex2bn(&message_task_5, "4C61756E63682061206D697373696C652E");
    // Alice public key (e, n), e = 010001, n = AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115
    BIGNUM* alice_public_key_n = BN_new();
    BN_hex2bn(&alice_public_key_n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

    // signature S = 643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F
    BIGNUM* S = BN_new();
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

    // Decrypt the signature using RSA
    BIGNUM* decrypted_signature = rsa_decrypt(S, modulus_e, alice_public_key_n);
    printf("Decrypted signature in task 5 is: ");
    printHX(BN_bn2hex(decrypted_signature));

    // corrupted signature S' = 643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F
    BIGNUM* S2 = BN_new();
    BN_hex2bn(&S2, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    // Decrypt the signature using RSA
    BIGNUM* decrypted_signature2 = rsa_decrypt(S2, modulus_e, alice_public_key_n);
    printf("Corrputed signature in task 5 is: ");
    printHX(BN_bn2hex(decrypted_signature2));

    printf("\n");


    /*
        Task 6: Manually Verifying an X.509 Certificate
    */

    // extracted the public key and modulus from the certificate at example.com
    

}