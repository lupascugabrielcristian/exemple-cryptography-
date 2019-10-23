# Helium, Bundsen Labs live cd, password live

#rsync -rzv -e 'ssh -o StrictHostKeyChecking=no' --filter='merge ./sync-filter.txt' ./ user@192.168.56.101:.
#rsync -rzv -e 'ssh -o StrictHostKeyChecking=no' --filter='merge ./sync-filter.txt' ./ root@192.168.56.102:.

# BlackArch
#rsync -rzv -e 'ssh -o StrictHostKeyChecking=no' --filter='merge ./sync-filter.txt' ./ root@10.0.2.15:.

# Network forensic
# set the password with sudo passwd nst
rsync -rzv -e 'ssh -o StrictHostKeyChecking=no' --filter='merge ./sync-filter.txt' ./ nst@192.168.56.106:.
