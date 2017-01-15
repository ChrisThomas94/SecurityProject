CSC3124 Systems Security Coursework (2015/2016)
Deadline: 17:00 Sunday 8th May 2016. Hand in via NESS.

Name: Chris Thomas
Student number: 120304288

Question 1: Protecting files using passwords

Key Implementation Aspects.

A startup function was defined to carry out the following:

•	Read through the given password file and hash every plaintext password, save these hashed passwords to separate files corresponding to the content files (i.e. BS13_password_hash.enc).

•	For every pair of passwords (key pair), generate 16 random bytes and using the hashed passwords as keys encrypt the random bytes. Store these encrypted values in files corresponding to the content files (i.e. BS13_AES.enc).

*This function was excluded from the submitted code as once the directory is setup it is not required anymore and is a potential threat to the security of the system. 

 
Figure 1 - Decryption Workflow

 
Figure 2 - Encryption Workflow

 
Figure 3 - Check Workflow
 
Bugs/Problems.
N/A

STRIDE Assessment.

Threat 1
Attack: An adversary accesses the USB stick in a state prior to encryption.

In this state the adversary can: 
•	Tamper with the files by changing the association between content files and password pairs. By swapping the contents of two files or changing the name of two files (i.e. BS13_password_hash.enc to TA_password_hash.enc and vice versa) the passwords used to encrypt/decrypt the content files will be swapped. 
•	Information Disclosure by reading the plaintext content files.

Likelihood: This attack relies on the amount of time it takes before all plaintext content files in the directory are encrypted. If the encryption process takes place immediately after startup, then this attack is extremely unlikely however if encryption is carried out hours or days after startup then the attack’s likelihood increases massively.  

Response: I have included a message that is displayed once the startup function has finished prompting the user to encrypt the files.

Threat 2
Attack: An adversary successfully guessing a decryption password.

•	The system is at risk of Information Disclosure if the password that is Spoofed is a decryption password as the adversary can now read the content file.
•	Tampering can take place if the password that is Spoofed is an encryption password as the adversary can now write to the content file.

Likelihood: If the password is strong then it is very unlikely but if the password is weak then it is more likely.

Response: Setting a maximum number of attempts a user can make before locking the USB stick.

Threat 3
Attack: Delete certain files from the directory, such as the AES keys which are required to encrypt and decrypt content files.

•	In doing so the adversary is performing a Denial of Service attack.

Likelihood: If the adversary has access to the directory then it is extremely likely however if they do not then it is extremely unlikely.

Response: An additional layer of security could be added, such as a password, to the USB stick, in order to initially gain access to its contents.

Threat 4
Attack: Accessing the password hash files stored within the directory.

•	In doing so the adversary can perform an Elevation of Privilege attack if they bypass the hash that Protect carries out on inputted passwords and inputs the password hash instead. 

Likelihood: It is unlikely that that an adversary would be able to bypass the hashing function applied to input passwords.

Response: In an ideal system the password hashes would be stored externally to the USB stick and checked over a network. 

Threat 5
Attack: Gain access to a content file by obtaining a plaintext password from the stored password hash.

•	The system is at risk of Information Disclosure if the password that is Spoofed is a decryption password as the adversary can now read the content file.
•	Tampering can take place if the password that is Spoofed is an encryption password as the adversary can now write to the content file.

Likelihood: It is fairly unlikely that this will happen but the hash function that is used (SHA-1) is fairly weak which makes it more likely.

Response: By including a salt in the hash process. 



Threat 6
Attack: If the adversary reads/deletes/changes anything, they cannot be identified and brought to justice.

•	The system is at risk of Repudiation as there is no method of proving who has performed an operation. 

Likelihood: Certain.

Response: By giving each individual user of the USB stick their own password they must enter in order to carry out any operations on the contents of the USB stick. Alternatively, by creating a role-based control policy as investigated in Question 2.

Other Remarks.
Password hashing could have been improved by including a salt. The salt would aid in protecting against dictionary attacks making it extremely difficult to spoof a password.  

Learning Outcomes.

Abstraction of Passwords: How to allow encryption and decryption of a file using two different passwords, one for encryption and another for decryption.
 
Question 2: Complex Access Control Policies

Key Implementation Aspects.

A number of auxiliary files were required for this question. I have created two text files for each content file in the directory, one of these files contains a list of the users who have read permissions for the related content file, the other a list of users who have write permissions. 

Three other files are required:
1.	Passwords list
2.	File list
3.	Role list
These files are used to initially set the role passwords, list the initial files in the directory and declare the initial roles.

A startup function is defined to carry out the following:

•	Read through the given password file and hash every plaintext password, replace the plaintext passwords with these hashed passwords. This password file should be maintained by the highest level of system admin.

The directory is now ready for any operations to be carried out. 

 
Figure 4 - Decryption Workflow
 
Figure 5 - Encryption Workflow

 
Figure 6 - Check Workflow
 
Bugs/Problems.
When hashing passwords in the password list, I found that if a new line did not exist at the end of the document the last password would not be hashed. This was solved by simply adding a blank line.

STRIDE Assessment.

Threat 1
Attack: Adding/removing roles to the read/write permissions files.

As a result, the adversary is:
•	Tampering the permissions files and as a result;
•	Elevating the privilege of all users if the adversary is adding roles.
•	Denying services to users if the adversary is removing roles.

Likelihood: Dependent on the security of these files.

Response: I have separated this information into separate files to allow for the possibility of distributing the management of these documents within the organization. This reduces the risk of an adversary obtaining access to all of these files, if the maintenance of the whole system rested on one file an adversary would only need to gain access to this file to control the whole system.

Threat 2
Attack: If the adversary reads/deletes/changes anything, there is a possibility that they won’t be successfully identified and brought to justice.

•	The system is at risk of Repudiation as there may be multiple users of each role. 

Likelihood: Less likely than the system in Question 1 but still likely that they won’t be successfully identified.

Response: Users must be identified more precisely for example using bioinformatics that will identify the user on a biological level and is much harder to repudiate.


Other Remarks.
I created an additional role for this task (user: chris, password: admin) to allow me to encrypt all files during start up due to the lack of permissions of the roles in the spec, the role was removed before submission.

The contents of auxiliary files such as the role list and the permission lists could have been hashed with a salt to increase the security of the system. Although displaying the list of roles in plaintext does not pose a direct threat to the system security, an adversary may be able to derive a password from the name given to the role (i.e. manager = universal and rookie = kiddo, are somewhat related). Being able to see the permissions of roles in the permission files aids the adversary by enabling them to decide which role they may wish to imitate digitally or intimidate physically (e.g. the manager has no write permissions and therefore isn’t of interest to an adversary who wishes to write to a file, however the analyst has some write permissions and as a result becomes a target of the adversary). 

Learning Outcomes.

Access Control Structure: As a result of the Access Control lecture I opted to use an Access Control list rather than a Matrix. As explained above it allows for distribution of responsibility.

Possible Attacks: As a result of analyzing the TREsPASS case study I was reminded that my system can be attacked physically via hardware and employees.  
 
Question 3: Security/Usability Tradeoff. 

Key Implementation Aspects. 

Similar to Question 2, I have created a new user role by adding an entry to the role list and declaring the password for that role in the password list. I then set the users permissions by adding the role to the relevant permission files.

Created a new function that executes when the new password (emergency) is used to decrypt a content file. The function deletes all files on the USB stick excluding the one specified when the operation is executed.

 
Figure 7 - Emergency Workflow
 
Bugs/Problems. 
N/A

STRIDE Assessment. 

Threat 1
Attack: Adversary misuses the emergency password. As a result, all but one file on that team’s USB stick will be deleted and will require the system admin to restore it. 

•	The system is at risk of Repudiation, if multiple users know the emergency password there is no way of identifying which user carried out the operation. 

Likelihood: If the adversary knows of the password and has the opportunity of entering it into the system the attack would be extremely likely.

Response: Limiting how frequently users can carry out this operation. Requiring some form of user identification in order to carry out the operation so the employee could be identified (i.e. password or bioinformatics).

Threat 2
Attack: An adversary could cause a denial of service by deleting the aux_file_list. When a user unknowingly executes the check operation (“-c”) the function would delete original auxiliary files preventing encryption and decryption to take place. 

Likelihood: Quite likely.

Response: Perform a check that the aux_file_list file exists before continuing with the operation, if it does not, then do not perform the operation. In order to further prevent the adversary from causing further denial of service a warning message is included instructing the user to seek the system administrator. 0 


Other Remarks. 
The threats outlines in the previous question also apply to this model.

Learning Outcomes. 

Access Control Structure: The Access Control lecture taught me how to add a new user to an access control list structure. 


