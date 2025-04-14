# LM-Studio-UI
Single Page php code file of front-end UI for LM-Studio

The user sessions are maintained in sessions.txt
The user accounts have to manually be created and added in users.txt as:
User1:<token>
Sample below:
John:dhYh5&6f_123UYFE%
Alice:EyjdhYf*(^kef1E%df

Set .htaccess with restriction. Sample content for .htaccess:
<FilesMatch "\.(txt|log|json)$">
  Order Allow,Deny
  Deny from all
</FilesMatch>

Logs folder to be created for storing logs in JSON format within text files with user name.
