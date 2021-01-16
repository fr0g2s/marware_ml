import pefile
#import sflock
import os
import sys
from datetime import datetime, date, time, timedelta

class PortableExecutable(object):
    '''
        Parse PE Structure

    '''
    def __init__(self, file_path):
        """@param file_path: file path."""
        self.file_path = file_path
        self.pe = None

    def _get_fileheaders(self):
        """Get fileheaders.
        @return: file headers
        """
        fileheaders = []

        try:
            machine = hex(self.pe.FILE_HEADER.Machine)
            if(machine == '0x14c'):
                machine_bits = '32'
            elif(machine == '0x8664'):
                machine_bits = '64'
            else:
                machine_bits = 'unknown'

            fileheaders.append({
                "machine": machine,
                "machine_bits": machine_bits
            })

            return fileheaders
        except:
            return None

    def _get_timestamp(self):
        """Get compilation timestamp.
        @return: timestamp or None.
        """
        if not self.pe:
            return None

        try:
            pe_timestamp = self.pe.FILE_HEADER.TimeDateStamp
        except AttributeError:
            return None

        return datetime.fromtimestamp(pe_timestamp).strftime("%Y-%m-%d %H:%M:%S")

    def _get_imported_symbols(self):
        """Get imported symbols.
        @return: imported symbols dict or None.
        """

        iat_lst = []

        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports_total = len(self.pe.DIRECTORY_ENTRY_IMPORT)
            if imports_total > 0:
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    symbols = []
                    for imp in entry.imports:
                        if (imp.name != None) and (imp.name != ""):
                            symbols.append({
                                "address": hex(imp.address),
                                "name": imp.name,
                            })
                    iat_lst.append({
                        "dll": str(entry.dll),
                        "imports": symbols,
                    })

        return iat_lst


    def _get_sections(self):
        """Get sections.
        @return: sections dict or None.
        """
        sections = []

        for entry in self.pe.sections:
            try:
                section = {}
                section["name"] = entry.Name.decode('utf-8').strip("\x00")
                section["virtual_address"] = "0x{0:08x}".format(entry.VirtualAddress)
                section["virtual_size"] = "0x{0:08x}".format(entry.Misc_VirtualSize)
                section["size_of_data"] = "0x{0:08x}".format(entry.SizeOfRawData)
                section["entropy"] = entry.get_entropy()
                sections.append(section)
            except:
                continue

        return sections

    def analysis(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return {}

        try:
            self.pe = pefile.PE(self.file_path)
        except pefile.PEFormatError:
            return {}

        results = {}
        results["pe_headers"] = self._get_fileheaders()
        results["pe_imports"] = self._get_imported_symbols()
        results["pe_sections"] = self._get_sections()

        return results
