#!/bin/bash

cd FinalCD/casper
unsquashfs filesystem.squashfs

#Copying the pool/, dists/, puppet_openstack_builder/, keys into chroot
cp -r ../pool/ squashfs-root/local-repo/
cp -r ../dists/ squashfs-root/local-repo/
cp -r ../puppet_openstack_builder/ squashfs-root/root/
mkdir squashfs-root/local-repo/keys/
cp ../../havate@havate.project-* squashfs-root/local-repo/keys/

cp /etc/resolv.conf squashfs-root/etc/
cp /etc/hosts squashfs-root/etc/
mount --bind /dev/ squashfs-root/dev
chroot squashfs-root <<EOF
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devpts none /dev/pts
export HOME=/root
export LC_ALL=C
dbus-uuidgen > /var/lib/dbus/machine-id
dpkg-divert --local --rename --add /sbin/initctl
ln -s /bin/true /sbin/initctl

#Configuring and Authenticating Local Repository
echo 'deb file:/local-repo precise main' > /etc/apt/sources.list
cat /local-repo/keys/havate\@havate.project-public-key | apt-key add -
apt-get update

apt-get install cobbler puppet git -y

cd /root/puppet_openstack_builder/install-scripts
./install.sh

apt-get clean
rm -rf /tmp/* ~/.bash_history
rm /etc/hosts
rm /etc/resolv.conf
rm /var/lib/dbus/machine-id
rm /sbin/initctl
dpkg-divert --rename --remove /sbin/initctl
#Do Stuff
umount /proc || umount -lf /proc
umount /sys
umount /dev/pts
exit
EOF

umount squashfs-root/dev
chmod +w filesystem.manifest
chroot squashfs-root dpkg-query -W --showformat='${Package} ${Version}\n' > filesystem.manifest
cp filesystem.manifest{,-desktop}
sed -i '/ubiquity/d' filesystem.manifest-desktop
sed -i '/casper/d' filesystem.manifest-desktop
rm filesystem.squashfs
mksquashfs squashfs-root/ filesystem.squashfs -comp lzo
printf $(sudo du -sx --block-size=1 squashfs-root | cut -f1) > filesystem.size
find -type f -print0 | sudo xargs -0 md5sum | grep -v olinux/boot.cat | sudo tee md5sum.txt
mkdir lztempdir
cd lztempdir
lzma -dc -S .lz ../initrd.lz | cpio -imvd --no-absolute-filenames

#Do stuff
find . | cpio --quiet --dereference -o -H newc | lzma -7 > ../initrd.lz


mksquashfs squashfs-root filesystem.squashfs -e boot

cd ../..

#Create diskdefines
echo "
define DISKNAME  LiveCD_COI
define TYPE  binary
define TYPEbinary  1
define ARCH  amd64
define ARCHamd64  1
define DISKNUM  1
define DISKNUM1  1
define TOTALNUM  0
define TOTALNUM0  1" > README.diskdefines

#base_installable is required for mounting ISO into USB stick
touch base_installable
echo "full_cd/single" > cd_type
echo "LiveCD COI" > info
echo "http//your-release-notes.com" > release_notes_url

(find . -type f -print0 | xargs -0 md5sum | grep -v "\./md5sum.txt" > md5sum.txt)

#Making Live ISO
mkisofs -r -V "LiveCD" -cache-inodes -l -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -o ../liveCD_COI.iso .
