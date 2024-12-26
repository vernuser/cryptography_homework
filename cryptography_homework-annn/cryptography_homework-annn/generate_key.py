from utils import generate_rsa_keypair, save_key

sender_private, sender_public = generate_rsa_keypair()
receiver_private, receiver_public = generate_rsa_keypair()

save_key('sender_private.pem', sender_private)
save_key('sender_public.pem', sender_public)
save_key('receiver_private.pem', receiver_private)
save_key('receiver_public.pem', receiver_public)
