package com.ohgiraffers.ex01.service;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.util.IOUtils;
import com.ohgiraffers.ex01.domain.MemberEntity;
import com.ohgiraffers.ex01.dto.MemberDTO;
import com.ohgiraffers.ex01.repo.MemberDataSet;
import com.ohgiraffers.ex01.repo.MemberRepo;
import com.ohgiraffers.ex01.utils.JwtUtil;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

@Service
@RequiredArgsConstructor
public class MemberService {
    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${s3.bucket}")
    private String bucket;
    private final AmazonS3 amazonS3;


    @Autowired
    MemberDataSet ds;
    private final MemberRepo repo;
    private final HttpSession session;
    private final PasswordEncoder passwordEncoder;

    final String DIR = "uploads/";

    public int insert(MemberDTO dto, MultipartFile file) {
        int result = 0;
        //result = ds.insert(dto);
        try {
            String fileName = null;
            if (file.isEmpty()) {
                fileName = "nan";
            } else {
                fileName = UUID.randomUUID().toString() + "-" +
                        file.getOriginalFilename();
            }
            dto.setFileName(fileName);

            String encodedPassword = passwordEncoder.encode(dto.getPassword());
            dto.setPassword(encodedPassword);

            repo.save(new MemberEntity(dto));
            result = 1;
            /*
            Path path = Paths.get(DIR+fileName);
            Files.createDirectories(path.getParent());
            if(!file.isEmpty()){
                file.transferTo(path);
            }
             */
            if (!file.isEmpty()) {
                ObjectMetadata metadata = new ObjectMetadata();
                metadata.setContentType(file.getContentType());
                metadata.setContentLength(file.getSize());
                amazonS3.putObject(bucket, dto.getFileName(), file.getInputStream(), metadata);
            }

        } catch (Exception e) {
            //throw new RuntimeException(e);
            e.printStackTrace();
        }
        return result;
    }

    public Map<String, Object> getList(int start) {
        start = start > 0 ? start - 1 : start;
        int size = 3; //한페이지 3개 글
        Pageable pageable = PageRequest.of(start, size,
                Sort.by(Sort.Order.desc("id")));
        Page<MemberEntity> page = repo.findAll(pageable);
        List<MemberEntity> listE = page.getContent();
        Map<String, Object> map = new HashMap<>();
        map.put("list", listE.stream().map(entity
                -> new MemberDTO(entity)).toList());
        map.put("totalPages", page.getTotalPages());
        map.put("currentPage", page.getNumber() + 1);
        return map;
        //return ds.getList();
        /*
        return repo.findAll().stream()
                .map( entity -> new MemberDTO(entity) )
                .toList();
         */
    }

    public int update(MemberDTO dto, String id) {
        if (dto.getUsername() == null || dto.getPassword() == null || dto.getRole() == null)
            return -1;

        MemberEntity entity = repo.findByUsername(dto.getUsername());
        if (entity != null) {
            //  비밀번호 암호화 후 저장
            String encodedPassword = passwordEncoder.encode(dto.getPassword());
            entity.setPassword(encodedPassword);

            entity.setRole(dto.getRole());
            repo.save(entity);
            return 1;
        }
        return 0;
    }


    // 파일 삭제
    public int mDelete(String id, String fileName) {
        //return ds.mDelete(id);
        MemberEntity entity = repo.findByUsername(id);
        if (entity != null) {
            repo.delete(entity);
            try {
                amazonS3.deleteObject(bucket, fileName);
                //Path filePath = Paths.get(DIR + fileName );
                //Files.deleteIfExists( filePath );//파일이 존재하면 삭제
            } catch (Exception e) {
                e.printStackTrace();
            }
            return 1;
        }
        return 0;
    }




    public Map<String, Object> login(String username, String password) {
        int result = -1;
        Map<String, Object> map = new HashMap<>();
        MemberEntity entity = repo.findByUsername(username);
        if (entity != null) {
            result = 1;
            if (passwordEncoder.matches(password, entity.getPassword())) {
                result = 0;
                map.put("token", JwtUtil.createJwt(username,
                        secretKey, entity.getRole()));
            }
        }
        map.put("result", result);
        return map;
    }

    public MemberDTO getOne(String username) {
        //MemberDTO dto = null;
        //dto = ds.getOne( username );
        //return dto;
        return new MemberDTO(repo.findByUsername(username));
    }

    //파일 다운로드
    public byte[] getImage(String fileName) {
        byte[] imageBytes = {0};
        try {
            // S3에서 파일 다운로드
            S3Object s3Object = amazonS3.getObject(new GetObjectRequest(bucket, fileName));
            imageBytes = IOUtils.toByteArray(s3Object.getObjectContent());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return imageBytes;
        /*
        Path filePath = Paths.get(DIR + fileName );
        byte[] imageBytes = {0};
        try {
        imageBytes = Files.readAllBytes( filePath );
        }catch (Exception e){
        e.printStackTrace();
        }
        return imageBytes;
        */
    }


}

