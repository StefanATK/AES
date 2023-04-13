function encode_AES()
	
	my_func_folder = 'meine_Funktionen';
	local_path = cd;
	user_path = userpath();
	
	full_my_func_folder = fullfile(user_path,my_func_folder);
	
	sp = split(local_path, filesep());
	
	new_folder = fullfile(full_my_func_folder,sp{end});
	if exist(new_folder, 'dir') ~= 7
		mkdir(new_folder);
	end
		
	pcode('AES.m');
	
	movefile('AES.p', new_folder);
end
