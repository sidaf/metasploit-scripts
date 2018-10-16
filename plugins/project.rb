# Original work Copyright (c) 2016, Carlos Perez <carlos_perez[at]darkoperator.com>
# Modified work Copyright (c) 2017 Sion Dafydd <sion.dafydd[at]gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted
# provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions and
# the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions
# and the following disclaimer in the documentation and/or other materials provided with the
# distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

module Msf
  class Plugin::Project < Msf::Plugin

    class ProjectCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      # Set name for command dispatcher
      def name
        'Project'
      end

      # Define Commands
      def commands
        {
            'project' => 'Manage projects.',
        }
      end

      def cmd_project_help
        print_line "Usage:"
        print_line "    project             List projects"
        print_line "    project -v          List projects verbosely"
        print_line "    project [name]      Switch project"
        print_line "    project -a [name]   Add project"
        print_line "    project -d [name]   Delete project"
        print_line "    project -D          Delete all projects"
        print_line "    project -e          Export project history and database and archive it"
        print_line "    project -r          Generate time stamped resource files containing session and console command history"
        print_line "    project -s          Generate time stamped session logs"
        print_line "    project -rs         Generate both time stamped resource files and session logs"
        #print_line "    project -r <old> <new>   Rename workspace"
        print_line "    project -h          Show this help information"
        print_line
      end

      def cmd_project(*args)
        # variable
        project_name = nil
        create = false
        delete = false
        delete_all = false
        verbose = false
        arch_path = ::File.join(Msf::Config.log_directory, 'archives')

        while (arg = args.shift)
          case arg
            when '-h','--help'
              cmd_project_help
              return
            when '-a','--add'
              create = true
            when '-d','--del'
              delete = true
            when '-D','--delete-all'
              project_list.each do |project|
                project_delete(project)
              end
              return
            when '-v','--verbose'
              list_verbose
              return
            when '-e', '--export'
              project_archive(arch_path)
              return
            when '-r', '--resource-files'
              make_console_rc
              make_sessions_rc
              return
            when '-s', '--session-logs'
              make_sessions_logs
              return
            when '-rs'
              make_console_rc
              make_sessions_rc
              make_sessions_logs
              return
            else
              project_name = arg.gsub(' ', '_').chomp
          end
        end

        if project_name and create
          project_create(project_name)
        elsif project_name and delete
          project_delete(project_name)
        elsif project_name
          project_switch(project_name)
        else
          list
        end
      end

      def project_delete(project_name)
        # Check if project exists
        if project_list.include?(project_name)
          current_workspace = framework.db.workspace.name
          if current_workspace == project_name
            driver.init_ui(driver.input, Rex::Ui::Text::Output::Stdio.new)
          end
          workspace = framework.db.find_workspace(project_name)
          if workspace.default?
            workspace.destroy
            workspace = framework.db.add_workspace(project_name)
            print_line('Deleted and recreated the default workspace')
          else
            # switch to the default workspace if we're about to delete the current one
            framework.db.workspace = framework.db.default_workspace if framework.db.workspace.name == workspace.name
            # now destroy the named workspace
            workspace.destroy
            print_line("Deleted workspace: #{project_name}")
          end
          project_path = ::File.join(Msf::Config.log_directory, 'projects', project_name)
          ::FileUtils.rm_rf(project_path)
          print_line("Project folder #{project_path} has been deleted")
        else
          print_error('Project was not found on list of projects!')
        end
        return true
      end

      # Switch to another project created by the plugin
      def project_switch(project_name)
        # Check if project exists
        if project_list.include?(project_name)
          print_line("Switching to #{project_name}")
          # Disable spooling for current
          driver.init_ui(driver.input, Rex::Ui::Text::Output::Stdio.new)

          # Switch workspace
          workspace = framework.db.find_workspace(project_name)
          framework.db.workspace = workspace
          print_line("Workspace: #{workspace.name}")

          # Spool
          spool_path = ::File.join(Msf::Config.log_directory, 'projects', framework.db.workspace.name)
          spool_file = ::File.join(spool_path, "#{project_name}_spool.log")

          # Start spooling for new workspace
          driver.init_ui(driver.input, Rex::Ui::Text::Output::Tee.new(spool_file))

          # Restore the prompt so we don't get "msf >  >".
          #prompt = framework.datastore['Prompt'] || Msf::Ui::Console::Driver::DefaultPrompt
          #prompt_char = framework.datastore['PromptChar'] || Msf::Ui::Console::Driver::DefaultPromptChar
          #if active_module # if there is an active module, give them the fanciness they have come to expect
          #  driver.update_prompt("#{prompt} #{mod.type}(%bld%red#{mod.shortname}%clr) ", prompt_char, true)
          #else
          #  driver.update_prompt("#{prompt} ", prompt_char, true)
          #end

          print_line("Spooling to file #{spool_file}...")
          print_line("Successfully migrated to #{project_name}")
        else
          print_error('Project was not found on list of projects!')
        end
        return true
      end

      # List current projects created by the plugin
      def list
        current_workspace = framework.db.workspace.name
        project_list.each do |p|
          if current_workspace == p
            print_line("%red* #{p}%clr")
          else
            print_line("  #{p}")
          end
        end
        return true
      end

      # Verbose list of current projects created by the plugin
      def list_verbose
        current_workspace = framework.db.workspace.name
        col_names = %w{current name hosts services vulns creds loots notes}

        tbl = Rex::Text::Table.new(
            'Header'     => 'Projects',
            'Columns'    => col_names,
            'SortIndex'  => -1
        )

        # List workspaces
        framework.db.workspaces.each do |ws|
          if project_list.include?(ws.name)
            tbl << [
                ws == current_workspace ? '   *   ' : '',
                ws.name,
                ws.hosts.count,
                ws.services.count,
                ws.vulns.count,
                ws.core_credentials.count,
                ws.loots.count,
                ws.notes.count
            ]
          end
        end

        print_line
        print_line(tbl.to_s)
        return true
      end

      # Archive project in to a zip file
      def project_archive(archive_path)
        # Set variables for options
        project_name = framework.db.workspace.name
        project_path = ::File.join(Msf::Config.log_directory, 'projects', project_name)
        archive_name = "#{project_name}_#{::Time.now.strftime('%Y%m%d.%H%M%S')}.zip"
        db_export_name = "#{project_name}_#{::Time.now.strftime('%Y%m%d.%H%M%S')}.xml"
        db_out = ::File.join(project_path, db_export_name)
        format = 'xml'
        print_line("Exporting DB Workspace #{project_name}")
        exporter = Msf::DBManager::Export.new(framework.db.workspace)
        exporter.send("to_#{format}_file".intern, db_out) do |mtype, mstatus, mname|
          if mtype == :status
            if mstatus == 'start'
              print_line("  >> Starting export of #{mname}")
            end
            if mstatus == 'complete'
              print_line("  >> Finished export of #{mname}")
            end
          end
        end
        print_line("Finished export of workspace #{framework.db.workspace.name} to #{db_out} [ #{format} ]...")
        print_line("Disabling spooling for #{project_name}")
        driver.init_ui(driver.input, Rex::Ui::Text::Output::Stdio.new)
        print_line('Spooling disabled for archiving')
        archive_full_path = ::File.join(archive_path, archive_name)
        make_console_rc
        make_sessions_rc
        make_sessions_logs
        compress(project_path, archive_full_path)
        print_line("MD5 for archive is #{digestmd5(archive_full_path)}")
        # Spool
        spool_path = ::File.join(Msf::Config.log_directory, 'projects', framework.db.workspace.name)
        spool_file = ::File.join(spool_path, "#{project_name}_spool.log")
        print_line('Spooling re-enabled')
        # Start spooling for new workspace
        driver.init_ui(driver.input, Rex::Ui::Text::Output::Tee.new(spool_file))

        # Restore the prompt so we don't get "msf >  >".
        #prompt = framework.datastore['Prompt'] || Msf::Ui::Console::Driver::DefaultPrompt
        #prompt_char = framework.datastore['PromptChar'] || Msf::Ui::Console::Driver::DefaultPromptChar
        #if active_module # if there is an active module, give them the fanciness they have come to expect
        #  driver.update_prompt("#{prompt} #{mod.type}(%bld%red#{mod.shortname}%clr) ", prompt_char, true)
        #else
        #  driver.update_prompt("#{prompt} ", prompt_char, true)
        #end
        print_line("Spooling to file #{spool_file}...")
        return true
      end

      # Create a new project Workspace and enable logging
      #-------------------------------------------------------------------------------------------
      def project_create(project_name)
        # Make sure that proper values where provided
        spool_path = ::File.join(Msf::Config.log_directory, 'projects', project_name)
        ::FileUtils.mkdir_p(spool_path)
        spool_file = ::File.join(spool_path, "#{project_name}_spool.log")
        if framework.db and framework.db.active
          print_line("Creating DB Workspace named #{project_name}")
          workspace = framework.db.add_workspace(project_name)
          framework.db.workspace = workspace
          print_line("Added workspace: #{workspace.name}")
          driver.init_ui(driver.input, Rex::Ui::Text::Output::Tee.new(spool_file))

          # Restore the prompt so we don't get "msf >  >".
          #prompt = framework.datastore['Prompt'] || Msf::Ui::Console::Driver::DefaultPrompt
          #prompt_char = framework.datastore['PromptChar'] || Msf::Ui::Console::Driver::DefaultPromptChar
          #if active_module # if there is an active module, give them the fanciness they have come to expect
          #  driver.update_prompt("#{prompt} #{mod.type}(%bld%red#{mod.shortname}%clr) ", prompt_char, true)
          #else
          #  driver.update_prompt("#{prompt} ", prompt_char, true)
          #end

          print_line("Spooling to file #{spool_file}...")
        else
          print_error('A database most be configured and connected to create a project')
        end
        return true
      end

      # Method for creating a console resource file from all commands entered in the console
      #-------------------------------------------------------------------------------------------
      def make_console_rc
        # Set RC file path and file name
        rc_file = "#{framework.db.workspace.name}_#{::Time.now.strftime('%Y%m%d.%H%M%S')}.rc"
        consonle_rc_path = ::File.join(Msf::Config.log_directory, 'projects', framework.db.workspace.name)
        rc_full_path = ::File.join(consonle_rc_path, rc_file)

        # Create folder
        ::FileUtils.mkdir_p(consonle_rc_path)
        con_rc = ''
        framework.db.workspace.events.each do |e|
          if not e.info.nil? and e.info.has_key?(:command) and not e.info.has_key?(:session_type)
            con_rc << "# command executed at #{e.created_at}\n"
            con_rc << "#{e.info[:command]}\n"
          end
        end

        # Write RC console file
        print_line("Writing Console RC file to #{rc_full_path}")
        file_write(rc_full_path, con_rc)
        print_line('RC file written')

        return rc_full_path
      end

      # Method for creating individual rc files per session using the session uuid
      #-------------------------------------------------------------------------------------------
      def make_sessions_rc
        sessions_uuids = []
        sessions_info = []
        info = ''
        rc_file = ''
        rc_file_name = ''
        rc_list =[]

        framework.db.workspace.events.each do |e|
          if not e.info.nil? and e.info.has_key?(:command) and e.info[:session_type] =~ /meter/
            if e.info[:command] != 'load stdapi'
              if not sessions_uuids.include?(e.info[:session_uuid])
                sessions_uuids << e.info[:session_uuid]
                sessions_info << {:uuid => e.info[:session_uuid],
                                  :type => e.info[:session_type],
                                  :id => e.info[:session_id],
                                  :info => e.info[:session_info]}
              end
            end
          end
        end

        sessions_uuids.each do |su|
          sessions_info.each do |i|
            if su == i[:uuid]
              print_line("Creating RC file for Session #{i[:id]}")
              rc_file_name = "#{framework.db.workspace.name}_session_#{i[:id]}_#{::Time.now.strftime('%Y%m%d.%H%M%S')}.rc"
              i.each do |k, v|
                info << "#{k.to_s}: #{v.to_s} "
              end
              break
            end
          end
          rc_file << "# Info: #{info}\n"
          info = ''
          framework.db.workspace.events.each do |e|
            if not e.info.nil? and e.info.has_key?(:command) and e.info.has_key?(:session_uuid)
              if e.info[:session_uuid] == su
                rc_file << "# command executed at #{e.created_at}\n"
                rc_file << "#{e.info[:command]}\n"
              end
            end
          end
          # Set RC file path and file name
          consonle_rc_path = ::File.join(Msf::Config.log_directory, 'projects', framework.db.workspace.name)
          rc_full_path = ::File.join(consonle_rc_path, rc_file_name)
          print_line("Saving RC file to #{rc_full_path}")
          file_write(rc_full_path, rc_file)
          rc_file = ''
          print_line('RC file written')
          rc_list << rc_full_path
        end

        return rc_list
      end

      # Method for exporting session history with output
      #-------------------------------------------------------------------------------------------
      def make_sessions_logs
        sessions_uuids = []
        sessions_info = []
        info = ''
        hist_file = ''
        hist_file_name = ''
        log_list = []

        # Create list of sessions with base info
        framework.db.workspace.events.each do |e|
          if not e.info.nil? and e.info[:session_type] =~ /shell/ or e.info[:session_type] =~ /meter/
            if e.info[:command] != 'load stdapi'
              if not sessions_uuids.include?(e.info[:session_uuid])
                sessions_uuids << e.info[:session_uuid]
                sessions_info << {:uuid => e.info[:session_uuid],
                                  :type => e.info[:session_type],
                                  :id => e.info[:session_id],
                                  :info => e.info[:session_info]}
              end
            end
          end
        end

        sessions_uuids.each do |su|
          sessions_info.each do |i|
            if su == i[:uuid]
              print_line("Exporting Session #{i[:id]} history")
              hist_file_name = "#{framework.db.workspace.name}_session_#{i[:id]}_#{::Time.now.strftime('%Y%m%d.%H%M%S')}.log"
              i.each do |k, v|
                info << "#{k.to_s}: #{v.to_s} "
              end
              break
            end
          end
          hist_file << "# Info: #{info}\n"
          info = ''
          framework.db.workspace.events.each do |e|
            if not e.info.nil? and e.info.has_key?(:command) or e.info.has_key?(:output)
              if e.info[:session_uuid] == su
                if e.info.has_key?(:command)
                  hist_file << "#{e.updated_at}\n"
                  hist_file << "#{e.info[:command]}\n"
                elsif e.info.has_key?(:output)
                  hist_file << "#{e.updated_at}\n"
                  hist_file << "#{e.info[:output]}\n"
                end
              end
            end
          end

          # Set RC file path and file name
          session_hist_path = ::File.join(Msf::Config.log_directory, 'projects', framework.db.workspace.name)
          session_hist_fullpath = ::File.join(session_hist_path, hist_file_name)

          # Create folder
          ::FileUtils.mkdir_p(session_hist_path)

          print_line("Saving log file to #{session_hist_fullpath}")
          file_write(session_hist_fullpath, hist_file)
          hist_file = ''
          print_line('Log file written')
          log_list << session_hist_fullpath
        end

        return log_list
      end

      # Compress a given folder given it's path
      #-------------------------------------------------------------------------------------------
      def compress(path, archive)
        require 'zip/zip'
        require 'zip/zipfilesystem'

        path.sub!(%r[/$], '')
        ::Zip::ZipFile.open(archive, 'w') do |zipfile|
          Dir["#{path}/**/**"].reject { |f| f==archive }.each do |file|
            print_line("Adding #{file} to archive")
            zipfile.add(file.sub(path+'/', ''), file)
          end
        end
        print_line("All files saved to #{archive}")
      end

      # Method to write string to file
      def file_write(file2wrt, data2wrt)
        if not ::File.exists?(file2wrt)
          ::FileUtils.touch(file2wrt)
        end

        output = ::File.open(file2wrt, 'a')
        data2wrt.each_line do |d|
          output.puts(d)
        end
        output.close
      end

      # Method to create MD5 of given file
      def digestmd5(file2md5)
        if not ::File.exists?(file2md5)
          raise "File #{file2md5} does not exists!"
        else
          require 'digest/md5'
          chksum = nil
          chksum = Digest::MD5.hexdigest(::File.open(file2md5, 'rb') { |f| f.read })
          return chksum
        end
      end

      # Method that returns a hash of projects
      def project_list
        project_folders = Dir::entries(::File.join(Msf::Config.log_directory, 'projects'))
        projects = []
        framework.db.workspaces.each do |s|
          if project_folders.include?(s.name)
            projects << s.name
          end
        end
        return projects
      end

    end

    def initialize(framework, opts)
      super
      if framework.db and framework.db.active
        add_console_dispatcher(ProjectCommandDispatcher)

        archive_path = ::File.join(Msf::Config.log_directory, 'archives')
        project_paths = ::File.join(Msf::Config.log_directory, 'projects')

        # Create project folder if first run
        if not ::File.directory?(project_paths)
          ::FileUtils.mkdir_p(project_paths)
        end

        # Create archive folder if first run
        if not ::File.directory?(archive_path)
          ::FileUtils.mkdir_p(archive_path)
        end

        print_status 'Project plugin version 1.5.0 loaded'
      else
        raise 'Database not connected (try db_connect)'
      end
    end

    def cleanup
      remove_console_dispatcher('Project')
    end

    def name
      'project'
    end

    def desc
      'Plugin for managing projects.'
    end

    protected
  end
end
