cd kernel
sudo make clean
sudo make
cd ..
cd user
gcc filebox.c -o filebox -lcrypto
cd ..
