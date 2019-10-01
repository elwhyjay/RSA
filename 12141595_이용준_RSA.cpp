#pragma warning(disable:4996)
#include <iostream>
#include <vector>
#include <time.h>
#include <math.h>
#include "xxhash.c"
#include <unordered_set>

using namespace std;

int gcd(int a, int b) { // �ִ�����
	if (a%b == 0) return b;
	return gcd(b, a%b);
}

int SquareandMultiply(int a, int x,int n) {
	if (x == 0)
		return 1;
	else if (x == 1)
		return a%n;
	else {
		unsigned long long r=1, p=a;
		while (x)
		{
			if (x & 1) // 1bit set�̸� ����
				r = (r*p) % n;
			p = (p*p) % n;
			x >>= 1;
		}
		return r;
	}
}
	

int ExtendedEuclideanAlgo(int a, int n) { // mod n ���� a�� ���� ������ ���Ѵ�.
	if (gcd(a, n) != 1)
		return -1;
	else {
		if (a > n) a = a % n;
		int s1 = 0, t1 = 1,s2=1,t2=-n/a;
		int r1= a, r2 = n%a,q=r1/r2;
		int tmp;
		while (r2 >1) {
			tmp = s2;
			s2 = s1 - s2 * q;
			s1 = tmp;
			tmp = t2;
			t2 = t1 - t2 * q;
			t1 = tmp;
			tmp = r2;
			r2 = r1 % r2;
			r1 = tmp;
			q = r1 / r2;
		}
		t2 = t2 % n;
		if (t2 < 0)
			t2 += n;
		return t2;
			
	}
}

bool miller_rabin(int n, int a) { //true -> probably prime
	int d = n - 1;
	while (d % 2 == 0) {
		if (SquareandMultiply(a, d, n) == n - 1)
			return true;
		d /= 2;
	}
	int tmp = SquareandMultiply(a, d, n);
	return tmp == n - 1 || tmp == 1;
}
bool is_prime(int n) { 
	if (n <= 1)
		return false;
	for (int i = 0; i < 20; i++) { //20 times test (2~)
		if (!miller_rabin(n, i + 2))
			return false;
	}
	return true;
}

int findE(int num) {//phi�� ���μ��� e�� ã�´�.
	int k;
	srand(time(NULL));
	while (1) {
		k = rand() % num;
		if (k <= 1) continue;
		if (gcd(num, k) == 1) return k;
	}
}
int Encryption(int m, int e, int mod) { //Encryption
	return SquareandMultiply(m, e, mod);
}
unsigned long long DShash(unsigned long long  M, unsigned long long mod) { //64bit hash������ 64bit �ڷ����� ����ؾ��Ѵ�
	char buf[65];
	sprintf(buf, "%I64u", M); 

	unsigned __int64 hash = XXH64(buf, sizeof(buf) - 1, 0);
	hash %= mod;
	if (hash < 0) hash += mod;
	return hash;
}
int Decryption(int C, int d, int p, int q, int r) { //CRTdecryptiong ,p,q,r are prime
	unsigned long long m1, m2, m3,x;
	unsigned long long c1 = SquareandMultiply(C, d % (p - 1), p),
		c2 = SquareandMultiply(C, d % (q - 1), q),
		c3 = SquareandMultiply(C, d % (r - 1), r);
	unsigned long long n = p * q*r;
	m1 = c1 * q*r*(ExtendedEuclideanAlgo(q*r, p)); // ps + tqr = 1�� t
	m2 = c2 * p*r*(ExtendedEuclideanAlgo(p*r, q)); 
	m3 = c3 * p*q*(ExtendedEuclideanAlgo(p*q, r));
	x = (m1+m2+m3) % n;
	return x;
}
int RSAsignature(int hash, int secretkey, int mod) {
	return SquareandMultiply(hash, secretkey, mod);
}
int main()
{
	srand(time(NULL));
	int p = rand() % 1024 , q = rand() % 1024 , r = rand() % 1024;// 10bit random�� ����
	vector<int> set;
	while (!is_prime(p)) { // miller rabin test��������� ���Ұ�� �ٽû���
		 p = rand() % 1024;
	}
	set.push_back(p);
	cout << "p : " << p;
	while (!is_prime(q)||set[0] == q) { // miller rabin test�� ����ϰ� p�� �ٸ� q�� ����
		 q = rand() % 1024;
	}
	set.push_back(q);
	cout << "\nq : " << q;
	while (!is_prime(r)||(set[0] == r)||(set[1] == r)) {// miller rabin test�� ����ϰ� p,q�� �ٸ� r�� ����
		 r = rand() % 1024; 
	}
	
	int N = p * q*r;
	int phi = (p - 1)*(q - 1)*(r - 1); //���Ϸ� - �����Լ�
	cout << "\nr : " << r << "\nN : " << N
		<< "\nphi : " << phi;
	
	int e;int d = 0;
	while (1) { // e�� ������ �������� ������ e�� �ٽ� ���� ������ ���Ѵ�.
		e = findE(phi);
		unsigned long long l;
		for (int i = 2; i < phi; i++)
		{
			l = i *(unsigned long long) e; 
			if ((l % phi) == 1) {
				d = i;
				break;
			}
		}
		if (d != 0) break;
	}
	clock_t start, end;
	cout << "\ne : " << e << "\nd : " << d;
	int M;
	cout << "\n\n\nMessage Input : ";
	cin >> M;
	cout << "Message : " << M;
	int cipher = Encryption(M, e, N);
	cout << "\n\n**Encryption\ncipher : " << cipher;
	unsigned long long hashValue = DShash(M, N);
	cout << "\n\n**Generate signature\nmessage's hash value : " << hashValue;
	//cipher += 1; message ����
	int sig = RSAsignature(hashValue, d, N);
	cout << "\ngenerated signature : " << sig << endl;
	/*��ȣȭ*/
	start = clock();
	unsigned long long decryptedCipher = Decryption(cipher, d, p,q,r);
	end = clock();
	double t1 = (double)(end - start);
	cout << "\n\n**Decryption\nCRTdecrypted cipher : " << decryptedCipher; // CRT��ȣȭ
	start = clock();
	cout << "\nEasy decrypted cipher : " << SquareandMultiply(cipher, d, N); // secret key�� �ٷ� ������ ���
	end = clock();
	double t2 = (double)(end - start);
	cout << "\nCRT Algorithm time : " << t1 << "\nOrdinary Algorithm time : " << t2;
	cout << "\n\n**Verify Signature\nreceived signature value : " << sig;
	/*���ڼ��� ���� ��ȣȭ�� �޼����� hash�Ѱ��� �־��� signature�� ����Ű�� ������ ���� ��*/
	int v1 = DShash(decryptedCipher, N);
	int v2 = SquareandMultiply(sig, e, N);
	cout << "\nmessage's hash value : " << hashValue << "\nverify value from signature : " << v2 << "\ndecrypted cipher's hash Value : " << v1;
	if (v1 == v2)
		cout << "\nSignature is valid\n";
	else
		cout << "\nSignature is not valid\n";
	
	
	
	
}