#!/usr/bin/env bash

# ==============================================================================
# secure-server.sh
# ------------------------------------------------------------------------------
# Copyright (C) 2019 Potherca
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.
# ==============================================================================

set -o errexit -o errtrace -o nounset -o pipefail

secure_server(){

    if [ "$(id -u)" != 0 ]; then
       echo "This script needs to be run as root." >&2
       exit 1
    fi

    sUserName="${1?Two parameters required: <user-name> <password>}"
    sPassword="${2?Two parameters required: <user-name> <password>}"

    sPath="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"

    # ==========================================================================
    # Setup users and user-groups
    # ==========================================================================

    # --------------------------------------------------------------------------
    # Create a group for ssh-users
    groupadd ssh-user

    # --------------------------------------------------------------------------
    # Create a regular user and add them to the sudo and ssh-user groups
    useradd                                              \
        --create-home                                    \
        --comment ''                                     \
        --groups 'ssh-user,sudo'                         \
        --password "$(openssl passwd -1 "${sPassword}")" \
        "${sUserName}"

    # ==========================================================================
    # Install Applications
    # ==========================================================================

    # --------------------------------------------------------------------------
    # Update the system
    # --------------------------------------------------------------------------
    apt-get update
    apt-get upgrade

    # --------------------------------------------------------------------------
    # Install Fail2Ban as it protects against sshd brute-force attacks 
    # --------------------------------------------------------------------------
    # Install google-authenticator to enable using 2FA (Two Factor Authentication)
    # --------------------------------------------------------------------------
    apt-get install \
        -y          \
        sudo        \
        fail2ban    \
        libpam-google-authenticator

    # --------------------------------------------------------------------------
    # Setup 2FA (Two Factor Authentication) for provided user
    sudo -u "${sUserName}"       \
        google-authenticator     \
            --disallow-reuse     \
            --emergency-codes=10 \
            --force              \
            --qr-mode=none       \
            --rate-limit=3       \
            --rate-time=30       \
            --time-based         \
            --window-size=5

    # ==========================================================================
    # Copy/Create/Remove files
    # ==========================================================================

    # --------------------------------------------------------------------------
    # Set up SSH banner
    cp "${sPath}/banner.txt" /etc/motd

    # --------------------------------------------------------------------------
    # Setup sshd configuration
    # --------------------------------------------------------------------------

    # Backup the original sshd settings
    mv /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

    # Use the suggested  sshd settings instead
    cp "${sPath}/sshd.conf" /etc/ssh/sshd_config

    # Make sure nothing is wrong with the changed SSH settings
    sshd -t || {
        echo "Please fix the problem stated above and run $0 again" >&2
        exit 64
    }

    # --------------------------------------------------------------------------
    # Setup Fail2Ban configuration
    cp "${sPath}/fail2ban.conf" /etc/fail2ban/jail.local

    # --------------------------------------------------------------------------
    # Add the Google Authenticator to the PAM rule file for SSH
    echo 'auth required pam_google_authenticator.so' >> /etc/pam.d/sshd

    # --------------------------------------------------------------------------
    # Regenerate Moduli used by SSH server for key exchange
    ssh-keygen -G moduli-2048.candidates -b 2048
    ssh-keygen -T moduli-2048 -f moduli-2048.candidates
    mv moduli-2048 /etc/ssh/moduli
    
    # --------------------------------------------------------------------------
    # Remove small Diffie-Hellman moduli
    awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
    mv /etc/ssh/moduli.safe /etc/ssh/moduli

    # ==============================================================================
    # Load the changed configuration by restarting services
    # ==============================================================================

    sudo service fail2ban restart
    sudo service ssh restart
    sudo systemctl reload sshd

    # ==============================================================================
    # If everything went well, lock the door behind us
    # ==============================================================================

    # --------------------------------------------------------------------------
    # Clear the history
    cat /dev/null > ~/.bash_history && history -c

    # --------------------------------------------------------------------------
    # Remove the password associated with the "root" user
    echo 'root:*' | chpasswd -e
}

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  export -f secure_server
else
  secure_server "${@}"
  exit $?
fi
# ==============================================================================
