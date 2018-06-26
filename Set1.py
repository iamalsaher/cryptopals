#!/usr/bin/env python2

import string
from Crypto.Cipher import AES

def c1(thestring):
	output=((thestring.decode('hex')).encode('base64')).strip()
	
	if output=='SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t':
		print ('[+]Set 1 Challenge 1 passed')
	return

def c2(thestring1, thestring2):
	thestring1=thestring1.decode('hex')
	thestring2=thestring2.decode('hex')
	final=''

	for i in range(len(thestring1)):
		final+=chr(ord(thestring1[i])^ord(thestring2[i])).encode('hex')
	
	if final=='746865206b696420646f6e277420706c6179':
		print ('[+]Set 1 Challenge 2 passed')
	return

def c3(thestring):
	thestring=thestring.decode('hex')
	upp=list(string.ascii_uppercase)	
	score={'z':2456495, 'q':3649838, 'j':4507165, 'x':5574077, 'k':22969448, 'v':30476191, 'b':47673928, 'p':55746578, 'y':59010696, 'g':61549736, 'w':69069021, 'f':72967175, 'm':79502870, 'c':79962026, 'u':88219598, 'l':125951672, 'd':134044565, 'r':184990759, 'h':193607737, 's':196844692, 'n':214319386, 'i':214822972, 'o':235661502, 'a':248362256, 't':282039486, 'e':390395169, ' ':700000000}
	maxscore=0
	finalstring=''
	for c in range(256):
		value=''
		finscore=0
		for i in range(len(thestring)):
			temp=chr(ord(thestring[i])^c)
			if temp in upp :finscore+=score[temp.lower()]
			elif temp in score: finscore+=score[temp]
			value+=temp

		if finscore > maxscore:
			maxscore=finscore
			finalstring=value
	
	print ('[+]Set 1 Challenge 3 passed')
	return

def c4(thestring):
	f=open(thestring,'r')
	maxscore=0
	value=''
	upp=list(string.ascii_uppercase)
	score={'z':2456495, 'q':3649838, 'j':4507165, 'x':5574077, 'k':22969448, 'v':30476191, 'b':47673928, 'p':55746578, 'y':59010696, 'g':61549736, 'w':69069021, 'f':72967175, 'm':79502870, 'c':79962026, 'u':88219598, 'l':125951672, 'd':134044565, 'r':184990759, 'h':193607737, 's':196844692, 'n':214319386, 'i':214822972, 'o':235661502, 'a':248362256, 't':282039486, 'e':390395169, ' ':700000000}
	
	for line in f:
		line=line.strip()
		line=line.decode('hex')
	
		for c in range(256):
			value=''
			finscore=0

			for i in range(len(line)):
				temp=chr(ord(line[i])^c)
				if temp in upp :finscore+=score[temp.lower()]
				elif temp in score: finscore+=score[temp]
				value+=temp

			if finscore > maxscore:
				maxscore=finscore
				finalstring=value

	print ('[+]Set 1 Challenge 4 passed')
	return

def c5(thestring):
	key="ICE"
	while len(key)<len(thestring):key+=key
	key=key[:len(thestring)]
	assert(len(key)==len(thestring))
	final=''
	for i in range(len(thestring)):
		final+=chr(ord(thestring[i])^ord(key[i])).encode('hex')

	if final=='0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f':
		print ('[+]Set 1 Challenge 5 passed')
	return

def editDistance(thestring1, thestring2):
	bin1=''
	bin2=''

	for i in thestring1:
		bin1+=bin(ord(i))[2:].zfill(8)

	for i in thestring2:
		bin2+=bin(ord(i))[2:].zfill(8)

	assert (len(bin1)==len(bin2))

	distance=0

	for i in range(len(bin1)):
		if bin1[i]!=bin2[i]:distance+=1
	
	return distance

def ret2(mytuple):
	return mytuple[1]

def scoreme(thestring):
	upp=list(string.ascii_uppercase)
	score={'z':2456495, 'q':3649838, 'j':4507165, 'x':5574077, 'k':22969448, 'v':30476191, 'b':47673928, 'p':55746578, 'y':59010696, 'g':61549736, 'w':69069021, 'f':72967175, 'm':79502870, 'c':79962026, 'u':88219598, 'l':125951672, 'd':134044565, 'r':184990759, 'h':193607737, 's':196844692, 'n':214319386, 'i':214822972, 'o':235661502, 'a':248362256, 't':282039486, 'e':390395169, ' ':700000000}
	finscore=0
	for char in thestring:
		if char in upp :finscore+=score[char.lower()]
		elif char in score: finscore+=score[char]
		else: continue
	return finscore

def c6(thestring):
	f=open(thestring,'r')
	text=''
	
	for line in f:
		text+=line.strip()
	
	text=text.decode('base64')
	fulllist=list()
	
	for i in range(2,41):
		distance=(editDistance(text[:i],text[i:2*i])+editDistance(text[i:2*i],text[2*i:3*i])+editDistance(text[2*i:3*i],text[3*i:4*i])+editDistance(text[3*i:4*i],text[4*i:5*i]))/i*4
		fulllist.append((i,distance))
	
	fulllist=sorted(fulllist, key=ret2)
	
	allval=list()

	for keysize in fulllist[:5]:
		keysize=keysize[0]
		singlepart=list()
		
		for i in range(keysize):
			temp=''
			for j in range(i,len(text),keysize):temp+=text[j]
			singlepart.append(temp)
		
		key=''
		
		for onestring in singlepart:
			maxscore=0
			# upp=list(string.ascii_uppercase)
			# score={'z':2456495, 'q':3649838, 'j':4507165, 'x':5574077, 'k':22969448, 'v':30476191, 'b':47673928, 'p':55746578, 'y':59010696, 'g':61549736, 'w':69069021, 'f':72967175, 'm':79502870, 'c':79962026, 'u':88219598, 'l':125951672, 'd':134044565, 'r':184990759, 'h':193607737, 's':196844692, 'n':214319386, 'i':214822972, 'o':235661502, 'a':248362256, 't':282039486, 'e':390395169, ' ':700000000}
			final=9090

			for c in range(256):
				finscore=0
				temp=''
				for i in range(len(onestring)):temp+=chr(ord(onestring[i])^c)
				
				finscore=scoreme(temp)


				if finscore > maxscore:
					maxscore=finscore
					final=c
			
			key+=chr(final)
		allval.append(key)
	
	maxscore=0
	finval=''
	finalkey=''
	for akey in allval:
		key=akey
		while len(key)<len(text):key+=key
		key=key[:len(text)]
		assert(len(key)==len(text))
			
		final=''
		for i in range(len(text)):final+=chr(ord(text[i])^ord(key[i]))
		finscore=scoreme(final)

		if finscore>maxscore:
			maxscore=finscore
			finval=final
			finalkey=akey
	
	print ('[+]Set 1 Challenge 6 passed')

def c7(thestring):
	f=open(thestring,'r')
	text=''
	
	for line in f:
		text+=line.strip()
	
	text=text.decode('base64')
	key = b'YELLOW SUBMARINE'
	cipher = AES.new(key, AES.MODE_ECB)
	msg = cipher.decrypt(text)
	print ('[+]Set 1 Challenge 7 passed')

def c8(thestring):
	f=open(thestring,'r')
	texts=[]
	
	for line in f:
		texts.append(line.strip().decode('hex'))
	
	maxval=0
	ecbtext="loremIpsumDolerImut"
	for ct in texts:
		blklist=list()
		for i in range(0,len(ct),16):blklist.append(ct[i:i+16].encode('hex'))
		tempval=0
		for i in range(len(blklist)):
			if blklist[i]=='loremipsum':continue
			for j in range(i+1,len(blklist)):
				if blklist[i]==blklist[j]:
					tempval+=1
					blklist[j]='loremipsum'
			blklist[i]='loremipsum'
			if tempval>maxval:
				maxval=tempval
				ecbtext=ct.encode('hex')
	
	print ('[+]Set 1 Challenge 8 passed')
		
if __name__=='__main__':
	c1("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	c2("1c0111001f010100061a024b53535009181c","686974207468652062756c6c277320657965")
	c3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	c4("4.txt")	
	c5("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	c6("6.txt")	
	c7("7.txt")
	c8("8.txt")