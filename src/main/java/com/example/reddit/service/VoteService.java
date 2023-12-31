package com.example.reddit.service;

import com.example.reddit.dto.VoteDto;
import com.example.reddit.exceptions.PostNotFoundException;
import com.example.reddit.exceptions.SpringRedditException;
import com.example.reddit.model.Post;
import com.example.reddit.model.Vote;
import com.example.reddit.model.VoteType;
import com.example.reddit.repository.PostRepository;
import com.example.reddit.repository.VoteRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import com.example.reddit.model.VoteType.*;

@Service
@AllArgsConstructor
public class VoteService {

    private final VoteRepository voteRepository;
    private final PostRepository postRepository;
    private final AuthService authService;

    @Transactional
    public void vote(VoteDto voteDto) {
        Post post=postRepository.findById(voteDto.getPostId()).orElseThrow(()-> new PostNotFoundException("Post Not Found with ID - " + voteDto.getPostId()));
        Optional<Vote> voteByPostAndUser=voteRepository.findTopByPostAndUserOrderByVoteIdDesc(post,authService.getCurrentUser());
        if (voteByPostAndUser.isPresent() && voteByPostAndUser.get().getVoteType().equals(voteDto.getVoteType())){
            throw new SpringRedditException("You have already "
                    + voteDto.getVoteType() + "'d for this post");
        }

        if(VoteType.UPVOTE.equals(voteDto.getVoteType())){
            post.setVoteCount(post.getVoteCount()+1);
        }else {
            post.setVoteCount(post.getVoteCount()-1);
        }

        voteRepository.save(mapToVote(voteDto,post));
        postRepository.save(post);
    }

    private Vote mapToVote(VoteDto voteDto,Post post){
        return Vote.builder().voteType(voteDto.getVoteType()).post(post).user(authService.getCurrentUser()).build();
    }
}
