// Copyright 2017 Sopium

// This file is part of TiTun.

// Based on Davide Brini's simpletun:
//
// http://backreference.org/2010/03/26/tuntap-interface-tutorial/
// http://backreference.org/wp-content/uploads/2010/03/simpletun.tar.bz2
//
// Copyright 2010 Davide Brini, and licensed under GPL v3.

// TiTun is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// TiTun is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with TiTun.  If not, see <https://www.gnu.org/licenses/>.

#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>

// Musl does not have linux/ headers.
// #include <linux/if_tun.h>

#define IFF_TUN         0x0001
#define IFF_TAP         0x0002
#define IFF_NO_PI       0x1000
#define TUNSETIFF     _IOW('T', 202, int)

/*
 Allocate a tun device.

 dev: name of tun device, or empty string if you do not wish to specify a name.

 Returns: fd of tun device, -1 on error, and errno is set appropriately.

 Actually device name will be written to name_out, at most name_len
 bytes will be written.
*/
int alloc_tun(const char *name, char* name_out, size_t name_len) {
    struct ifreq ifr;
    int fd, errno_save;

    if ((fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC)) < 0)
         return -1;

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0 ) {
        errno_save = errno;
        close(fd);
        errno = errno_save;
        return -1;
    }

    strncpy(name_out, ifr.ifr_name, name_len);

    return fd;
}
